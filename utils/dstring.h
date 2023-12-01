#ifndef DSTRING_H
#define DSTRING_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>


#define DSTRING_INIT_CAPACITY 16;

typedef struct {
    size_t length;
    size_t capacity;
    char *data;
} dstring_t;

void dstring_init(dstring_t *dstring);
void dstring_add(dstring_t *dstring, const char *string);
size_t dstring_printf(dstring_t *dstring, const char *format, ...);
void dstring_clear(dstring_t *dstring);
void dstring_free(dstring_t *dstring);

#endif