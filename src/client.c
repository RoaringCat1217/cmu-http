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

#include <parse_http.h>
#include <test_error.h>
#include <ports.h>

#include "net_helper.h"
#include "rio.h"
#include "nonblocking_io.h"

#define MAX_LINE 1024
#define BUF_SIZE 8192
#define CONNECTION_TIMEOUT 50

#define N_THREADS 8

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
    
    /* Set up a connection to the HTTP server */
    int http_sock;
    struct sockaddr_in http_server;
    if ((http_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return TEST_ERROR_HTTP_CONNECT_FAILED;
    }
    http_server.sin_family = AF_INET;
    http_server.sin_port = htons(HTTP_PORT);
    inet_pton(AF_INET, argv[1], &(http_server.sin_addr));
    
    fprintf(stderr, "Parsed IP address of the server: %X\n", htonl(http_server.sin_addr.s_addr));

    if (connect (http_sock, (struct sockaddr *)&http_server, sizeof(http_server)) < 0){
        return TEST_ERROR_HTTP_CONNECT_FAILED;
    }

    // pipe_fds[i][j][k]:
    // i: thread id
    // j: 0 for worker read master write, 1 for master read worker write
    // k: 0 for read, 1 for write
    int pipe_fds[N_THREADS][2][2];

    /* CP1: Send out a HTTP request, waiting for the response */

}