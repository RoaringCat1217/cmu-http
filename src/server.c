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
#include <sys/mman.h>
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

#define YIELD 0
#define FINISH 1

typedef struct {
    nio_t nio;
    int state;
    vector_t req_buf;
    Request request;
    size_t nleft;
} routine_data_t;

int conncount = 0;
struct pollfd fds[MAX_CONNECTION + 1];
routine_data_t routine_data_arr[MAX_CONNECTION + 1];

fileset_t fileset;

int routine(routine_data_t *routine_data);
void write_http_400(nio_t *nio);
void write_http_404(nio_t *nio);
void write_http_503(nio_t *nio, bool instant);
int get_header_value(Request request, char *header_name, char *header_value);
test_error_code_t parse_header(char *buf, size_t size, Request *request);
void serve(char *buf, size_t size, nio_t *nio);

int routine(routine_data_t *routine_data) {
    while (true) {
        if (routine_data->state == 0) {
            // initialize routine_data
            vector_init(&routine_data->req_buf);
            routine_data->request.body = NULL;
            routine_data->request.headers = NULL;
            routine_data->state = 2;
            continue;
        }

        if (routine_data->state == 1) {
            // free routine_data, and return
            vector_free(&routine_data->req_buf);
            if (routine_data->request.body != NULL)
                free(routine_data->request.body);
            if (routine_data->request.headers != NULL)
                free(routine_data->request.headers);
            return FINISH;
        }

        if (routine_data->state == 2) {
            // read request header line
            ssize_t nread =
                nio_readline(&routine_data->nio, &routine_data->req_buf);
            if (nread == 0) {
                if (routine_data->req_buf.size != 0)
                    serve((char *)routine_data->req_buf.data,
                          routine_data->req_buf.size, NULL);
                routine_data->state = 1;
                continue;
            }
            if (nread == NOT_READY)
                return YIELD;

            routine_data->state = 3;
            continue;
        }

        if (routine_data->state == 3) {
            // read headers and parse headers
            ssize_t nread =
                nio_readline(&routine_data->nio, &routine_data->req_buf);
            if (nread == 0) {
                serve((char *)routine_data->req_buf.data,
                      routine_data->req_buf.size, NULL);
                routine_data->state = 1;
                continue;
            }
            if (nread == NOT_READY)
                return YIELD;
            if (nread == 2) {
                // read \r\n, headers finished
                test_error_code_t err = parse_header(
                    (char *)routine_data->req_buf.data,
                    routine_data->req_buf.size, &routine_data->request);
                if (err != TEST_ERROR_NONE) {
                    serve((char *)routine_data->req_buf.data,
                          routine_data->req_buf.size, &routine_data->nio);
                    routine_data->state = 1;
                    continue;
                }
                if (strcmp(routine_data->request.http_method, GET) == 0 ||
                    strcmp(routine_data->request.http_method, HEAD) == 0) {
                    // do not need to receive body, serve the client
                    serve((char *)routine_data->req_buf.data,
                          routine_data->req_buf.size, &routine_data->nio);
                    vector_clear(&routine_data->req_buf);
                    routine_data->state = 2;
                    continue;
                } else if (strcmp(routine_data->request.http_method, POST) ==
                           0) {
                    // POST, need to receive body
                    char content_length[4096];
                    if (get_header_value(routine_data->request,
                                         "Content-Length",
                                         content_length) == -1) {
                        // header doesn't contain Content-Length
                        serve((char *)routine_data->req_buf.data,
                              routine_data->req_buf.size, &routine_data->nio);
                        routine_data->state = 1;
                    } else {
                        routine_data->nleft = atoi(content_length);
                        routine_data->state = 4;
                    }
                    continue;
                } else {
                    serve((char *)routine_data->req_buf.data,
                          routine_data->req_buf.size, &routine_data->nio);
                    routine_data->state = 1;
                    continue;
                }
            }
            continue;
        }

        if (routine_data->state == 4) {
            // read data for body
            ssize_t nread =
                nio_readb(&routine_data->nio, &routine_data->req_buf,
                          routine_data->nleft);
            if (nread == 0) {
                serve((char *)routine_data->req_buf.data,
                      routine_data->req_buf.size, NULL);
                routine_data->state = 1;
                continue;
            }
            if (nread == NOT_READY)
                return YIELD;
            routine_data->nleft -= nread;
            printf("%zu\n", routine_data->nleft);
            if (routine_data->nleft > 0)
                continue;
            // received all the body
            serve((char *)routine_data->req_buf.data,
                  routine_data->req_buf.size, &routine_data->nio);
            vector_clear(&routine_data->req_buf);
            routine_data->state = 2;
            continue;
        }
    }
}

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
    fileset_init(&fileset, www_folder);
    char path_to_file[MAX_LINE];
    char file_name[MAX_LINE];
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
        if (strcmp(".", entry->d_name) == 0 ||
            strcmp("..", entry->d_name) == 0) {
            continue;
        }
        strcpy(path_to_file + len, entry->d_name);
        file_name[0] = '/';
        strcpy(file_name + 1, entry->d_name);
        fileset_insert(&fileset, file_name, path_to_file);
    }
    closedir(www_dir);

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

    while (1) {
        int ret = poll(fds, conncount + 1, CONNECTION_TIMEOUT);
        if (ret < 0) {
            fprintf(stderr, "poll: %d, %s\n", errno, strerror(errno));
            exit(1);
        }

        for (int i = 0; i < conncount + 1; i++) {
            // handle client drop
            if (fds[i].revents & POLLHUP || fds[i].revents & POLLERR) {
                int fd = fds[i].fd;
                fds[i] = fds[conncount];
                routine_data_arr[i] = routine_data_arr[conncount];
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

                if (conncount >= MAX_CONNECTION) {
                    // send back HTTP 503 and close connection right away
                    nio_t nio;
                    nio_init(&nio, conn);
                    write_http_503(&nio, true);
                    close(conn);
                } else {
                    conncount++;
                    fds[conncount].fd = conn;
                    fds[conncount].events = POLLIN | POLLHUP | POLLERR;
                    fds[conncount].revents = 0;

                    // allocate space for a new routine_data
                    routine_data_arr[conncount].state = 0;
                    nio_init(&routine_data_arr[conncount].nio,
                             fds[conncount].fd);
                }
            } else if (fds[i].revents & POLLIN) {
                routine(&routine_data_arr[i]);
            } else if (fds[i].revents & POLLOUT) {
                nio_writeb(&routine_data_arr[i].nio, NULL, 0);
            }

            if (fds[i].fd != listenfd) {
                if (routine_data_arr[i].nio.rclosed &&
                    routine_data_arr[i].nio.wbuf.size == 0) {
                    int fd = fds[i].fd;
                    fds[i] = fds[conncount];
                    routine_data_arr[i] = routine_data_arr[conncount];
                    i--;
                    conncount--;
                    close(fd);
                    printf("delete connection - 2: %d\n", fd);
                } else if (routine_data_arr[i].nio.wbuf.size == 0) {
                    // continue to read data
                    fds[i].events &= (~POLLOUT);
                    fds[i].events |= POLLIN;
                } else if (routine_data_arr[i].nio.wbuf.size > 0) {
                    // continue to write data
                    fds[i].events &= (~POLLIN);
                    fds[i].events |= POLLOUT;
                }
            }
        }
    }

    return EXIT_SUCCESS;
}

void write_http_400(nio_t *nio) {
    char *msg;
    size_t len;
    nio->rclosed = true;

    if (serialize_http_response(&msg, &len, BAD_REQUEST, NULL, NULL, NULL, 0,
                                NULL) == TEST_ERROR_NONE) {
        nio_writeb_pushback(nio, (uint8_t *)msg, len);
        free(msg);
    }
}

void write_http_404(nio_t *nio) {
    char *msg;
    size_t len;
    nio->rclosed = true;

    if (serialize_http_response(&msg, &len, NOT_FOUND, NULL, NULL, NULL, 0,
                                NULL) == TEST_ERROR_NONE) {
        nio_writeb_pushback(nio, (uint8_t *)msg, len);
        free(msg);
    }
}

void write_http_503(nio_t *nio, bool instant) {
    char *msg;
    size_t len;
    nio->rclosed = true;

    if (serialize_http_response(&msg, &len, SERVICE_UNAVAILABLE, NULL, NULL,
                                NULL, 0, NULL) == TEST_ERROR_NONE) {
        if (instant) {
            nio_writeb(nio, (uint8_t *)msg, len);
        } else {
            nio_writeb_pushback(nio, (uint8_t *)msg, len);
        }
        free(msg);
    }
}

int get_header_value(Request request, char *header_name, char *header_value) {
    for (int i = 0; i < request.header_count; i++) {
        if (strncasecmp(request.headers[i].header_name, header_name,
                        strlen(header_name)) == 0) {
            // ignore the leading space
            strcpy(header_value, request.headers[i].header_value + 1);
            return 0;
        }
    }
    return -1;
}

test_error_code_t parse_header(char *buf, size_t size, Request *request) {
    if (request == NULL)
        return TEST_ERROR_NONE;

    test_error_code_t error_code = parse_http_request(buf, size, request);
    if (error_code == TEST_ERROR_NONE && request->valid) {
        return TEST_ERROR_NONE;
    } else {
        return error_code;
    }
}

void serve(char *buf, size_t size, nio_t *nio) {
    Request request;
    test_error_code_t error_code = parse_http_request(buf, size, &request);

    if (error_code == TEST_ERROR_NONE && request.valid) {
        if (strcmp(request.http_version, HTTP_VER) != 0) {
            write_http_400(nio);
            return;
        }
        if (strcmp(request.http_method, GET) == 0 ||
            strcmp(request.http_method, HEAD) == 0) {
            size_t uri_len = strlen(request.http_uri);
            if (request.http_uri[uri_len - 1] == '/') {
                strcpy(request.http_uri + uri_len, "index.html");
            }
            int file_fd = fileset_find(&fileset, request.http_uri);
            if (file_fd == -1) {
                char file_path[MAX_LINE];
                sprintf(file_path, "%s%s", fileset.root, request.http_uri);
                file_fd = open(file_path, O_RDONLY);
                if (file_fd > 0) {
                    fileset_insert(&fileset, request.http_uri, file_path);
                }
            }

            if (file_fd < 0) {
                // file not found
                write_http_404(nio);
                return;
            } else {
                if (strcmp(request.http_method, GET) == 0) {
                    // get file length
                    int file_len = lseek(file_fd, 0, SEEK_END);
                    // get mapping
                    char *addr = mmap(NULL, file_len, PROT_READ, MAP_PRIVATE,
                                      file_fd, 0);
                    char *data = malloc(file_len); // data stores file content
                    memcpy(data, addr, file_len);  // copy file content

                    munmap(addr, file_len);

                    char *msg;
                    size_t len;
                    char content_len[MAX_LINE];
                    sprintf(content_len, "%d", file_len);

                    if (serialize_http_response(&msg, &len, OK, NULL,
                                                content_len, NULL, file_len,
                                                data) == TEST_ERROR_NONE) {
                        nio_writeb_pushback(nio, (uint8_t *)msg, len);
                        free(msg);
                    }
                    free(data);
                } else {
                    char *msg;
                    size_t len;

                    if (serialize_http_response(&msg, &len, OK, NULL, NULL,
                                                NULL, 0,
                                                NULL) == TEST_ERROR_NONE) {
                        nio_writeb_pushback(nio, (uint8_t *)msg, len);
                        free(msg);
                    }
                }
            }
        } else if (strcmp(request.http_method, POST) == 0) {
            char content_length[4096];
            int err =
                get_header_value(request, "Content-Length", content_length);
            if (err == -1) {
                // if a post request doesn't contain content-length
                write_http_400(nio);
                return;
            } else {
                nio_writeb_pushback(nio, (uint8_t *)buf, size);
            }
        } else {
            write_http_400(nio);
            return;
        }
        char connection_status[MAX_LINE];
        get_header_value(request, CONNECTION_STR, connection_status);
        if (strncasecmp(connection_status, CLOSE, strlen(CLOSE)) == 0) {
            nio->rclosed = true;
            return;
        }
    } else {
        // parse error
        write_http_400(nio);
        return;
    }
}
