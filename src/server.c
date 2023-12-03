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
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "dstring.h"
#include "fileset.h"
#include "net_helper.h"
#include "parse_http.h"
#include "ports.h"

#include "nonblocking_io.h"

#define MAX_LINE 1024
#define BUF_SIZE 8192
#define CONNECTION_TIMEOUT 50
#define MAX_CONNECTION 100

typedef struct {
    nio_t nio;
    int progress;
} routine_data_t;

struct pollfd fds[MAX_CONNECTION + 1];
int conncount = 0;
fileset_t fileset;

void routine(routine_data_t *routine_data);

void serve();

int main(int argc, char *argv[]) {
    /* Validate and parse args */
    if (argc != 2) {
        fprintf(stderr, "usage: %s <www-folder>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *www_folder = argv[1];

    DIR *www_dir = opendir(www_folder);
    if (www_dir == NULL) {
        fprintf(stderr, "Unable to open www folder %s.\n", www_folder);
        return EXIT_FAILURE;
    }

    // open all files and store their fds in fileset
    fileset_init(&fileset);
    char path_to_file[MAX_LINE];
    strcpy(path_to_file, www_folder);
    size_t len = strlen(path_to_file);
    // make sure it ends with /
    if (path_to_file[len - 1] != '/') {
        path_to_file[len] = '/';
        len++;
        path_to_file[len] = '\0';
    }
    struct dirent *entry;
    while ((entry = readdir(www_dir)) != NULL) {
        strcpy(path_to_file + len, entry->d_name);
        fileset_insert(&fileset, path_to_file);
    }
    closedir(www_dir);

    /* CP1: Set up sockets and read the buf */
    char port[6];
    sprintf(port, "%d", HTTP_PORT);
    const int listenfd = open_listenfd(port);
    if (listenfd < 0) {
        fprintf(stderr, "Failed to listen on port: %s\n", port);
        exit(1);
    }

    fds[0].fd = listenfd;
    fds[0].events = POLLIN | POLLERR;
    fds[0].revents = 0;

    // Signal(SIGPIPE, sigpipe_handler);

    while (1) {
        int ret = poll(fds, conncount + 1, -1);
        if (ret < 0) {
            fprintf(stderr, "poll: %d, %s\n", errno, strerror(errno));
            exit(1);
        }

        for (int i = 0; i < conncount + 1; i++) {
            // handle client drop
            if ((fds[i].revents & POLLHUP) || (fds[i].revents & POLLERR)) {
                int fd = fds[i].fd;
                fds[i] = fds[conncount];
                i--;
                conncount--;
                close(fd);
                printf("delete connection: %d\n", fd);
            } else if ((fds[i].fd == listenfd) && (fds[i].revents & POLLIN)) {
                // accept and initialize a new routine
                struct sockaddr_in client;
                socklen_t lenaddr = sizeof(client);
                int conn = -1;

                if (-1 == (conn = accept(listenfd, (struct sockaddr *)&client,
                                         &lenaddr))) {
                    fprintf(stderr, "accept: %d, %s\n", errno, strerror(errno));
                    exit(1);
                }
                printf("get connection %d from %s:%d\n", conn,
                       inet_ntoa(client.sin_addr), client.sin_port);

                if (conncount == MAX_CONNECTION) {
                    // send back HTTP 503 and close connection
                } else {
                    conncount++;
                    fds[conncount].fd = conn;
                    fds[conncount].events = POLLIN | POLLHUP | POLLERR;
                    fds[conncount].revents = 0;

                    // allocate space for a new routine_data
                    routine_data_t *routine_data =
                        malloc(sizeof(routine_data_t));
                    routine_data->progress = 0;
                    nio_init(&routine_data->nio, fds[conncount].fd);
                }
            } else if (fds[i].revents & POLLIN) {

            } else if (fds[i].revents & POLLOUT) {
            }

            // determine write buffer is empty or not
            // if empty, fds[i].events &= (~POLLIN);
            //           fds[i].events |= POLLOUT;
            // if not empty, fds[i].events &= (~POLLIN);
            //               fds[i].events |= POLLOUT;
        }
    }

    return EXIT_SUCCESS;
}

void write_http_400(nio_t *nio) {
    char *msg;
    size_t len;

    if (serialize_http_response(&msg, &len, BAD_REQUEST, NULL, NULL, NULL, 0,
                                NULL) == TEST_ERROR_NONE) {
        vector_push_back(&nio->wbuf, (uint8_t *)msg, len);
    }
}

void write_http_404(nio_t *nio) {
    char *msg;
    size_t len;

    if (serialize_http_response(&msg, &len, NOT_FOUND, NULL, NULL, NULL, 0,
                                NULL) == TEST_ERROR_NONE) {
        vector_push_back(&nio->wbuf, (uint8_t *)msg, len);
    }
}

void write_http_503(nio_t *nio) {
    char *msg;
    size_t len;

    if (serialize_http_response(&msg, &len, SERVICE_UNAVAILABLE, NULL, NULL,
                                NULL, 0, NULL) == TEST_ERROR_NONE) {
        vector_push_back(&nio->wbuf, (uint8_t *)msg, len);
    }
}

test_error_code_t parse_header(char *buf, size_t size, Request request) {
    test_error_code_t error_code = parse_http_request(buf, size, &request);

    if (error_code == TEST_ERROR_NONE && request.valid) {
        return TEST_ERROR_NONE;
    } else {
        return error_code;
    }
}

void serve(char *buf, size_t size, nio_t *nio) {
    Request request;
    test_error_code_t error_code = parse_http_request(buf, size, &request);

    if (error_code == TEST_ERROR_NONE && request.valid) {

        if (strcmp(request.http_method, GET) == 0) {

        } else if (strcmp(request.http_method, HEAD) == 0) {

        } else if (strcmp(request.http_method, POST) == 0) {
        }
    } else {
        // parse error
    }
}
