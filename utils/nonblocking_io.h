#ifndef NONBLOCKING_IO_H
#define NONBLOCKING_IO_H

#include <stdint.h>
#include <stdbool.h>

#include "vector.h"
#include "dstring.h"

#define NOT_READY -1

typedef struct {
    int fd;
    vector_t rbuf;
    vector_t wbuf;
    bool rclosed;
} nio_t;

void nio_init(nio_t *nio, int fd);
// read as much as possible from fd
ssize_t nio_read(nio_t *nio);
// read as much as possible from nio and store at most n bytes of data to usrbuf. If n == -1, store all the data to usrbuf
ssize_t nio_readb(nio_t *nio, vector_t *usrbuf, ssize_t n);
// read until reaching a '\n' and store data to line (including '\n'). LINE IS NOT A STRING!!!
ssize_t nio_readline(nio_t *nio, vector_t *line);
// write as much as possible to fd
ssize_t nio_writeb(nio_t *nio, const uint8_t *usrbuf, size_t size);
// append some backs to the write buffer
ssize_t nio_writeb_pushback(nio_t *nio, const uint8_t *usrbuf, size_t size);
// NOT responsible to close the fd!!!
void nio_free(nio_t *nio);

#endif