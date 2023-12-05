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
#include "str_queue.h"

#define MAX_LINE 1024
#define BUF_SIZE 8192
#define CONNECTION_TIMEOUT 50

#define N_CONNS 8

#define YIELD 0
#define FINISH 1

// hostname and port
char hostname[MAX_LINE];
char port[MAX_LINE];
// save files to ./www/ folder
char save_path[] = "./www/";

typedef struct {
    // initialize / free by the main loop
    nio_t nio;
    int state;
    str_queue_t *tasks;
    // initialize / free by the routine
    vector_t resp_buf;  // response headers
    vector_t file_buf;  // file responded by the server
} routine_data_t;

void build_request(Request *request, const char *filename, const char *hostname);
void send_request(nio_t *nio, const char *filename);
int routine(routine_data_t *data, bool terminate);
bool init_routine(routine_data_t *conn, struct pollfd *pollfd, str_queue_t *tasks);
void clean_routine(routine_data_t *conn);

int main(int argc, char *argv[]) {
    /* Validate and parse args */
    if (argc != 2) {
        fprintf(stderr, "usage: %s <server-ip>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // task queue
    str_queue_t tasks;
    str_queue_init(&tasks);

    // set up connections and routine_data
    routine_data_t conns[N_CONNS];
    struct pollfd pollfds[N_CONNS];
    for (int i = 0; i < N_CONNS; i++) {
        if (!init_routine(&conns[i], &pollfds[i], &tasks)) {
            fprintf(stderr, "connection %d failed\n", i);
            exit(1);
        }
    }

    // store file dependency
    dependency_graph_t graph;
    graph_init(&graph);

    // next connection to assign a task to
    int next_conn = 0;

    // request "dependency.csv"
    send_request(&conns[next_conn].nio, "dependency.csv");
    if (conns[next_conn].nio.wbuf.size > 0)
        pollfds[next_conn].events |= POLLOUT;
    next_conn = (next_conn + 1) % N_CONNS;

    while (true) {
        int ret = poll(pollfds, N_CONNS, CONNECTION_TIMEOUT);
        if (ret < 0) {
            fprintf(stderr, "poll: %d, %s\n", errno, strerror(errno));
            exit(1);
        }
        for (int i = 0; i < N_CONNS; i++) {
            if ((pollfds[i].revents & POLLHUP) || (pollfds[i].revents & POLLERR)) {
                // connection terminated by server unexpectedly
                clean_routine(&conns[i]);
                // try to reconnect once
                if (!init_routine(&conns[i], &pollfds[i], &tasks)) {
                    fprintf(stderr, "connection %d failed\n", i);
                    exit(1);
                }
            }
            if (pollfds[i].revents & POLLIN) {
                int status = routine(&conns[i], false);
                if (status == FINISH) {
                    // server closed its read end unexpectedly
                    clean_routine(&conns[i]);
                    // try to reconnect once
                    if (!init_routine(&conns[i], &pollfds[i], &tasks)) {
                        fprintf(stderr, "connection %d failed\n", i);
                        exit(1);
                    }
                }
            }
            if (pollfds[i].revents & POLLOUT)
                nio_writeb(&conns[i].nio, NULL, 0);
        }

    }

    return 0;
}

void send_request(nio_t *nio, const char *filename) {
    Request request;
    build_request(&request, filename, hostname);
    char reqbuf[BUF_SIZE];
    size_t buf_size;
    serialize_http_request(reqbuf, &buf_size, &request);
    nio_writeb(nio, (uint8_t *)reqbuf, buf_size);
    if (request.headers != NULL) {
        free(request.headers);
        request.headers = NULL;
    }
    if (request.body != NULL) {
        free(request.body);
        request.body = NULL;
    }
}

void build_request(Request *request, const char *filename, const char *hostname) {
    strcpy(request->http_version, HTTP_VER);
    strcpy(request->http_method, GET);
    sprintf(request->http_uri, "/%s", filename);
    strcpy(request->host, hostname);
    request->allocated_headers = 15;
    request->headers = (Request_header *) malloc(sizeof(Request_header) * request->allocated_headers);
    strcpy(request->headers[0].header_name, "Connection");
    strcpy(request->headers[0].header_value, "Keep-Alive");
    request->header_count = 1;
    request->status_header_size = 0;
    request->body = NULL;
    request->valid = true;
}

bool init_routine(routine_data_t *conn, struct pollfd *pollfd, str_queue_t *tasks) {
    int fd = open_clientfd(hostname, port);
    if (fd < 0)
        return false;
    nio_init(&conn->nio, fd);
    conn->state = 0;
    conn->tasks = tasks;
    pollfd->fd = fd;
    pollfd->events = POLLIN | POLLHUP | POLLERR;
    pollfd->revents = 0;
    return true;
}

void clean_routine(routine_data_t *conn) {
    // let the routine exit gracefully
    routine(conn, true);
    close(conn->nio.fd);
    nio_free(&conn->nio);
}

int routine(routine_data_t *data, bool terminate) {
    if (terminate)
        data->state = 1;
    while (true) {
        if (data->state == 0) {
            // initialize
            vector_init(&data->resp_buf);
            vector_init(&data->file_buf);
            data->state = 3;
            continue;
        }

        if (data->state == 1) {
            // free resources
            vector_free(&data->resp_buf);
            vector_free(&data->file_buf);
            return FINISH;
        }

        if (data->state == 2) {
            // clean up structures, then read the next server response
            vector_clear(&data->resp_buf);
            vector_clear(&data->file_buf);
            data->state = 3;
            continue;
        }

        if (data->state == 3) {
            // read server response

        }
    }
}