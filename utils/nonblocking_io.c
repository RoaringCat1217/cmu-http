#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "nonblocking_io.h"

#define BUF_SIZE 1024

void nio_init(nio_t *nio, int fd) {
    // set fd as non-blocking
    int flags = fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);

    nio->fd = fd;
    vector_init(&nio->rbuf);
    vector_init(&nio->wbuf);
    nio->rclosed = false;
}

ssize_t nio_read(nio_t *nio) {
    if (nio->rclosed)
        return 0;
    uint8_t buf[BUF_SIZE];
    ssize_t nread = 0, tot = 0;
    while (true) {
        nread = read(nio->fd, buf, BUF_SIZE);
        if (nread > 0) {
            vector_push_back(&nio->rbuf, buf, nread);
            tot += nread;
            continue;
        }
        if (nread == 0) {
            nio->rclosed = true;
            return tot;
        }
        if (nread == -1) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (tot > 0)
                    return tot;
                return NOT_READY;
            }
        }
        return -2;
    }
}

ssize_t nio_readb(nio_t *nio, vector_t *usrbuf) {
    ssize_t nread = nio_read(nio);
    if (nio->rbuf.size > 0) {
        nread = nio->rbuf.size;
        vector_push_back(usrbuf, nio->rbuf.data, nio->rbuf.size);
        vector_clear(&nio->rbuf);
    }
    return nread;
}

ssize_t nio_readline(nio_t *nio, vector_t *line) {
    ssize_t nread = nio_read(nio);
    int i = 0;
    for (; i < nio->rbuf.size; i++)
        if (nio->rbuf.data[i] == '\n')
            break;
    if (i < nio->rbuf.size) {
        // found \n
        vector_push_back(line, nio->rbuf.data, i + 1);
        vector_pop_front(&nio->rbuf, i + 1);
        return i + 1;
    }
    if (nread == 0)
        return 0;
    return NOT_READY;
}

ssize_t nio_writeb(nio_t *nio, const uint8_t *usrbuf, size_t size) {
    if (usrbuf != NULL && size > 0)
        vector_push_back(&nio->wbuf, usrbuf, size);
    while (nio->wbuf.size > 0) {
        ssize_t nwrite = write(nio->fd, nio->wbuf.data, nio->wbuf.size);
        if (nwrite >= 0)
            return nwrite;
        if (nwrite == -1) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return NOT_READY;
        }
        return -2;
    }
    return 0;
}

void nio_free(nio_t *nio) {
    vector_free(&nio->rbuf);
    vector_free(&nio->wbuf);
}