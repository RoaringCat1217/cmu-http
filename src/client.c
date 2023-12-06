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
#include <sys/stat.h>
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

#define N_CONNS 1

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
    dependency_graph_t *graph;
    str_queue_t *tasks;  // append new tasks to this queue
    str_queue_t mytasks;  // stores sent by unresponded files
    int *nrecv;
    // initialize / free by the routine
    vector_t resp_buf;  // response headers
    vector_t file_buf;  // file responded by the server
    Response response;
} routine_data_t;

void build_request(Request *request, const char *filename, const char *hostname);
void send_request(routine_data_t *conn, const char *filename);
int routine(routine_data_t *data, bool terminate);
bool init_routine(routine_data_t *conn, struct pollfd *pollfd, dependency_graph_t *graph, str_queue_t *tasks, int *nrecv);
void clean_routine(routine_data_t *conn);

int main(int argc, char *argv[]) {
    /* Validate and parse args */
    if (argc != 2) {
        fprintf(stderr, "usage: %s <server-ip>\n", argv[0]);
        return EXIT_FAILURE;
    }

    strcpy(hostname, argv[1]);
    sprintf(port, "%d", HTTP_PORT);

    // create ./www/ directory
    if (mkdir(save_path, 0777) < 0 && errno != EEXIST) {
        fprintf(stderr, "cannot create directory\n");
        return EXIT_FAILURE;
    }

    // store file dependency
    dependency_graph_t graph;
    graph_init(&graph);

    // task queue
    str_queue_t tasks;
    str_queue_init(&tasks);

    // how many files have been received
    int nrecv = 0;

    // set up connections and routine_data
    routine_data_t conns[N_CONNS];
    struct pollfd pollfds[N_CONNS];
    for (int i = 0; i < N_CONNS; i++) {
        if (!init_routine(&conns[i], &pollfds[i], &graph, &tasks, &nrecv)) {
            fprintf(stderr, "connection %d failed\n", i);
            exit(1);
        }
    }

    // next connection to assign a task to
    int next_conn = 0;

    // request "dependency.csv"
    send_request(&conns[next_conn], "dependency.csv");
    next_conn = (next_conn + 1) % N_CONNS;
    if (conns[next_conn].nio.wbuf.size > 0)
        pollfds[next_conn].events |= POLLOUT;

    bool finished = false;
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
                if (!init_routine(&conns[i], &pollfds[i], &graph, &tasks, &nrecv)) {
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
                    if (!init_routine(&conns[i], &pollfds[i], &graph, &tasks, &nrecv)) {
                        fprintf(stderr, "connection %d failed\n", i);
                        exit(1);
                    }
                } else {
                    if (graph.size == 0 && nrecv == 1) {
                        // received dependency.csv
                        nrecv = 0;
                        int fd = open("./www/dependency.csv", O_RDONLY);
                        rio_t rio;
                        rio_readinitb(&rio, fd);
                        char line[MAX_LINE];
                        char val[MAX_LINE] = "\0", key[MAX_LINE] = "\0";
                        while (rio_readlineb(&rio, line, MAX_LINE) > 0) {
                            sscanf(line, "%[^,],%s", val, key);
                            graph_insert(&graph, key, val);
                        }
                        // push tasks to task queue
                        key_file_t *key_file = graph_find(&graph, "");
                        for (value_file_t *val_file = key_file->values; val_file != NULL; val_file = val_file->next)
                            str_queue_push(&tasks, val_file->filename);
                    } else if (nrecv == graph.nfiles) {
                        // received all files
                        finished = true;
                        break;
                    } else {
                        // check if there are tasks to assign
                        while (tasks.size > 0) {
                            char *task = str_queue_pop(&tasks);
                            send_request(&conns[next_conn], task);
                            free(task);
                            next_conn = (next_conn + 1) % N_CONNS;
                        }
                    }
                }
            }

            if (pollfds[i].revents & POLLOUT)
                nio_writeb(&conns[i].nio, NULL, 0);
        }
        if (finished)
            break;

        for (int i = 0; i < N_CONNS; i++) {
            if (conns[i].nio.wbuf.size > 0)
                pollfds[i].events |= POLLOUT;
            else
                pollfds[i].events &= (~POLLOUT);
        }
    }

    str_queue_free(&tasks);
    for (int i = 0; i < N_CONNS; i++)
        clean_routine(&conns[i]);
    graph_free(&graph);

    return 0;
}

void send_request(routine_data_t *conn, const char *filename) {
    Request request;
    build_request(&request, filename, hostname);
    char reqbuf[BUF_SIZE];
    size_t buf_size;
    serialize_http_request(reqbuf, &buf_size, &request);
    nio_writeb(&conn->nio, (uint8_t *)reqbuf, buf_size);
    if (request.headers != NULL) {
        free(request.headers);
        request.headers = NULL;
    }
    if (request.body != NULL) {
        free(request.body);
        request.body = NULL;
    }
    str_queue_push(&conn->mytasks, filename);
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

bool init_routine(routine_data_t *conn, struct pollfd *pollfd, dependency_graph_t *graph, str_queue_t *tasks, int *nrecv) {
    int fd = open_clientfd(hostname, port);
    if (fd < 0)
        return false;
    nio_init(&conn->nio, fd);
    conn->state = 0;
    conn->graph = graph;
    conn->tasks = tasks;
    str_queue_init(&conn->mytasks);
    conn->nrecv = nrecv;
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
    str_queue_free(&conn->mytasks);
}

int routine(routine_data_t *data, bool terminate) {
    if (terminate) {
        if (data->state != 1)
            data->state = 1;
        else
            return FINISH;
    }
    while (true) {
        if (data->state == 0) {
            // initialize
            printf("routine: entered state 0\n");
            vector_init(&data->resp_buf);
            vector_init(&data->file_buf);
            data->response.headers = NULL;
            data->response.body = NULL;
            data->state = 3;
            continue;
        }

        if (data->state == 1) {
            // free resources
            printf("routine: entered state 1\n");
            vector_free(&data->resp_buf);
            vector_free(&data->file_buf);
            if (data->response.headers != NULL) {
                free(data->response.headers);
                data->response.headers = NULL;
            }
            if (data->response.body != NULL) {
                free(data->response.body);
                data->response.body = NULL;
            }
            return FINISH;
        }

        if (data->state == 2) {
            printf("routine: entered state 2\n");
            // received one file
            data->nrecv++;
            // clean up structures, then read the next server response
            vector_clear(&data->resp_buf);
            vector_clear(&data->file_buf);
            if (data->response.headers != NULL) {
                free(data->response.headers);
                data->response.headers = NULL;
            }
            if (data->response.body != NULL) {
                free(data->response.body);
                data->response.body = NULL;
            }
            data->state = 3;
            continue;
        }

        if (data->state == 3) {
            printf("routine: entered state 3\n");
            // read the first line of response
            ssize_t nread =
                    nio_readline(&data->nio, &data->resp_buf);
            if (nread == 0) {
                data->state = 1;
                continue;
            }
            if (nread == NOT_READY)
                return YIELD;
            data->state = 4;
            continue;
        }

        if (data->state == 4) {
            printf("routine: entered state 4\n");
            // read headers
            ssize_t nread = nio_readline(&data->nio, &data->resp_buf);
            if (nread == 0) {
                data->state = 1;
                continue;
            }
            if (nread == NOT_READY)
                return YIELD;
            if (nread == 2) {
                // read \r\n
                test_error_code_t err = parse_http_response((char *)data->resp_buf.data, data->resp_buf.size, &data->response);
                if (err != TEST_ERROR_NONE || strcasecmp(data->response.staus_text, "ok") != 0) {
                    free(str_queue_pop(&data->mytasks));
                    data->state = 2;
                    continue;
                }
                vector_push_back(&data->resp_buf, (uint8_t *)"\0", 1);
                printf("\n%s\n\n", (char *)data->resp_buf.data);
                data->state = 5;
                continue;
            }
        }

        if (data->state == 5) {
            printf("routine: entered state 5\n");
            // receiving body
            size_t nleft = data->response.body_size - data->file_buf.size;
            printf("nleft=%lu\n", nleft);
            ssize_t nread = nio_readb(&data->nio, &data->file_buf, nleft);
            if (nread == 0) {
                data->state = 1;
                continue;
            }
            if (data->file_buf.size < data->response.body_size)
                return YIELD;
            // received the entire file
            char path_to_file[MAX_LINE];
            char *filename = str_queue_pop(&data->mytasks);
            sprintf(path_to_file, "%s%s", save_path, filename);
            // write the file
            int fd = open(path_to_file, O_WRONLY | O_CREAT | O_TRUNC);
            rio_writen(fd, data->file_buf.data, data->file_buf.size);
            close(fd);
            // add new tasks to tasks
            key_file_t *key = graph_find(data->graph, filename);
            for (value_file_t *val = key->values; val != NULL; val = val->next)
                str_queue_push(data->tasks, val->filename);
            free(filename);

            data->state = 2;
            continue;
        }
    }
}