/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the HTTP course project developed for
 * the Computer Networks course (15-441/641) taught at Carnegie
 * Mellon University.
 *
 * No part of the HTTP project may be copied and/or distributed
 * without the express permission of the 15-441/641 course staff.
 */
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>

#include <parse_http.h>
#include <test_error.h>
#include <ports.h>

#include "net_helper.h"
#include "rio.h"
#include "nonblocking_io.h"
#include "file_dependency.h"

#define MAX_LINE 1024
#define BUF_SIZE 8192
#define CONNECTION_TIMEOUT 50

#define N_THREADS 8

const char path[] = "./www/";

typedef struct {
    int id;
    int rmaster_fd;
    int wmaster_fd;
    const char *hostname;
    const char *port;
} args_t;

void build_request(Request *request, const char *filename, const char *hostname) {
    strcpy(request->http_version, HTTP_VER);
    strcpy(request->http_method, GET);
    strcpy(request->http_uri, "/");
    strcpy(request->http_uri + 1, filename);
    strcpy(request->host, hostname);
    request->header_count = 0;
    request->status_header_size = 0;
    request->allocated_headers = 15;
    request->headers = (Request_header *) malloc(sizeof(Request_header) * request->allocated_headers);
    request->body = NULL;
    request->valid = true;
}

void *thread(void *args) {
    args_t *thread_args = (args_t *)args;
    int id = thread_args->id;
    rio_t rmaster;
    rio_readinitb(&rmaster, thread_args->rmaster_fd);
    int wmaster = thread_args->wmaster_fd;
    int socket_fd = open_clientfd(thread_args->hostname, thread_args->port);
    nio_t socket;
    nio_init(&socket, socket_fd);

    struct pollfd fds[2];
    fds[0].fd = rmaster.rio_fd;
    fds[0].events = POLLIN | POLLHUP | POLLERR;
    fds[1].fd = socket.fd;
    fds[1].events = POLLIN | POLLHUP | POLLERR;

    while (true) {
        int ret = poll(fds, 2, CONNECTION_TIMEOUT);
        if (ret < 0) {
            fprintf(stderr, "poll: %d, %s\n", errno, strerror(errno));
            exit(1);
        }

        if ((fds[0].revents & POLLHUP) || (fds[0].revents & POLLERR))
            // master closed, jobs done
            break;
        if (fds[0].revents & POLLIN) {
            // build a request, send immediately
            char filename[MAX_LINE];
            ssize_t nread;
            nread = rio_readlineb(&rmaster, filename, MAX_LINE);
            // trim '\n'
            filename[nread - 1] = '\0';
            Request request;
            build_request(&request, filename, thread_args->hostname);
            char reqbuf[BUF_SIZE];
            size_t buf_size;
            serialize_http_request(reqbuf, &buf_size, &request);
            nio_writeb(&socket, (uint8_t *)reqbuf, buf_size);
            if (request.headers != NULL) {
                free(request.headers);
                request.headers = NULL;
            }
            if (request.body != NULL) {
                free(request.body);
                request.body = NULL;
            }
        }

        if ((fds[1].revents & POLLHUP) || (fds[1].revents & POLLERR))
            break;

        if (fds[1].revents & POLLIN) {
            // received response from server

        }
    }
}

int main(int argc, char *argv[]) {
    /* Validate and parse args */
    if (argc != 2) {
        fprintf(stderr, "usage: %s <server-ip>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *hostname = argv[1];
    char port[MAX_LINE];
    sprintf(port, "%d", HTTP_PORT);

    // pipe_fds[i][j][k]:
    // i: thread id
    // j: 0 for worker read master write, 1 for master read worker write
    // k: 0 for read, 1 for write
    int pipe_fds[N_THREADS][2][2];
    for (int i = 0; i < N_THREADS; i++) {
        pipe(pipe_fds[i][0]);
        pipe(pipe_fds[i][1]);
    }

    // thread args
    args_t args[N_THREADS];
    for (int i = 0; i < N_THREADS; i++) {
        args[i].id = i;
        args[i].rmaster_fd = pipe_fds[i][0][0];
        args[i].wmaster_fd = pipe_fds[i][1][1];
        args[i].hostname = hostname;
        args[i].port = port;
    }

    // rios and fds, used to communicate with workers
    rio_t rio[N_THREADS];
    for (int i = 0; i < N_THREADS; i++)
        rio_readinitb(&rio[i], pipe_fds[i][1][0]);
    struct pollfd read_fds[N_THREADS];
    for (int i = 0; i < N_THREADS; i++) {
        read_fds[i].fd = pipe_fds[i][1][0];
        read_fds[i].events = POLLIN | POLLHUP | POLLERR;
    }
    int write_fds[N_THREADS];
    for (int i = 0; i < N_THREADS; i++)
        write_fds[i] = pipe_fds[i][0][1];

    // launch threads
    pthread_t threads[N_THREADS];
    for (int i = 0; i < N_THREADS; i++)
        pthread_create(&threads[i], NULL, thread, (void *)&args[i]);

    dependency_graph_t graph;
    graph_init(&graph);
    // next thread to assign a task to
    int next_thread = 0;
    // no need to send "\0" here. rio_readlineb will append \0 automatically
    rio_writen(write_fds[next_thread], "dependency.csv\n", strlen("dependency.csv\n"));
    next_thread = (next_thread + 1) % N_THREADS;
    int nreceive = 0;
    bool finished = false;

    while (true) {
        int ret = poll(read_fds, N_THREADS, CONNECTION_TIMEOUT);
        if (ret < 0) {
            fprintf(stderr, "poll: %d, %s\n", errno, strerror(errno));
            exit(1);
        }
        for (int i = 0; i < N_THREADS; i++) {
            if ((read_fds[i].revents & POLLHUP) || (read_fds[i].revents & POLLERR)) {
                fprintf(stderr, "thread %d exited unexpectedly\n", i);
                exit(1);
            }
            if (read_fds[i].revents & POLLIN) {
                char filename[MAX_LINE];
                ssize_t nread = rio_readlineb(&rio[i], filename, MAX_LINE);
                // trim '\n'
                filename[nread - 1] = '\0';
                if (strcmp(filename, "dependency.csv") == 0) {
                    // read dependency file
                    int fd = open("./www/dependency.csv", O_RDONLY);
                    char line[MAX_LINE], key[MAX_LINE], val[MAX_LINE];
                    rio_t csv_io;
                    rio_readinitb(&csv_io, fd);
                    while (rio_readlineb(&csv_io, line, MAX_LINE) > 0) {
                        key[0] = '\0';
                        val[0] = '\0';
                        sscanf(line, "%[^,],%s", val, key);
                        graph_insert(&graph, key, val);
                    }
                    // request files with no dependency
                    key_file_t *node = graph_find(&graph, "");
                    for (value_file_t *val_file = node->values; val_file != NULL; val_file = val_file->next) {
                        sprintf(line, "%s\n", val_file->filename);
                        rio_writen(write_fds[next_thread], line, strlen(line));
                        next_thread = (next_thread + 1) % N_THREADS;
                    }
                } else {
                    nreceive++;
                    if (nreceive == graph.nfiles) {
                        finished = true;
                        break;
                    }
                    key_file_t *node = graph_find(&graph, filename);
                    char line[MAX_LINE];
                    for (value_file_t *val_file = node->values; val_file != NULL; val_file = val_file->next) {
                        sprintf(line, "%s\n", val_file->filename);
                        rio_writen(write_fds[next_thread], line, strlen(line));
                        next_thread = (next_thread + 1) % N_THREADS;
                    }
                }
            }
        }
        if (finished)
            break;
    }

    // join threads
    for (int i = 0; i < N_THREADS; i++) {
        close(rio[i].rio_fd);
        close(write_fds[i]);
    }
    for (int i = 0; i < N_THREADS; i++)
        pthread_join(threads[i], NULL);

    return 0;
}