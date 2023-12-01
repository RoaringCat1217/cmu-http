#ifndef RIO_H
#define RIO_H

/* Robust I/O (Rio) package - stolen from 15513 Proxy Lab */

#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>


/* Persistent state for the robust I/O (Rio) package */
#define RIO_BUFSIZE 8192
typedef struct {
    int rio_fd;                /* Descriptor for this internal buf */
    ssize_t rio_cnt;           /* Unread bytes in internal buf */
    char *rio_bufptr;          /* Next unread byte in internal buf */
    char rio_buf[RIO_BUFSIZE]; /* Internal buffer */
} rio_t;

// rio_readn - Robustly read n bytes (unbuffered)
ssize_t rio_readn(int fd, void *usrbuf, size_t n);
// rio_writen - Robustly write n bytes (unbuffered)
ssize_t rio_writen(int fd, const void *usrbuf, size_t n);
// rio_readinitb - Associate a descriptor with a read buffer and reset buffer
void rio_readinitb(rio_t *rp, int fd);
// rio_readnb - Robustly read n bytes (buffered)
ssize_t rio_readnb(rio_t *rp, void *usrbuf, size_t n);
// rio_readlineb - Robustly read a text line (buffered)
ssize_t rio_readlineb(rio_t *rp, void *usrbuf, size_t maxlen);

#endif