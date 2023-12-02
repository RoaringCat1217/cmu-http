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

#include "fileset.h"
#include "net_helper.h"
#include "parse_http.h"
#include "ports.h"

#include <nonblocking_io.h>

#define MAX_LINE 1024
#define BUF_SIZE 8192
#define CONNECTION_TIMEOUT 50
#define MAX_CONNECTION 100

struct pollfd fds[MAX_CONNECTION];

int setnoblock(int fd);

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
    fileset_t fileset;
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
    int conncount = 0;

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
                conncount++;
                setnoblock(conn);
                fds[conncount].fd = conn;
                fds[conncount].events = POLLIN | POLLHUP | POLLERR;
                fds[conncount].revents = 0;
            }
        }
    }

    return EXIT_SUCCESS;
}
