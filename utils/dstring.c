#include "dstring.h"

void dstring_init(dstring_t *dstring) {
    dstring->capacity = DSTRING_INIT_CAPACITY;
    dstring->length = 0;
    dstring->data = malloc(dstring->capacity);
    dstring->data[0] = '\0';
}

void dstring_add(dstring_t *dstring, const char *string) {
    size_t length = strlen(string);
    bool grow = false;
    while (dstring->length + length + 1 > dstring->capacity) {
        grow = true;
        dstring->capacity *= 2;
    }
    if (grow)
        dstring->data = realloc(dstring->data, dstring->capacity);
    strcpy(dstring->data + dstring->length, string);
    dstring->length += length;
}

size_t dstring_printf(dstring_t *dstring, const char *format, ...) {
    va_list args;
    va_start(args, format);
    size_t n = vsnprintf(dstring->data + dstring->length, dstring->capacity - dstring->length, format, args);
    bool grow = false;
    while (n >= dstring->capacity - dstring->length) {
        grow = true;
        dstring->capacity *= 2;
    }
    if (grow) {
        dstring->data = realloc(dstring->data, dstring->capacity);
        n = vsnprintf(dstring->data + dstring->length, dstring->capacity - dstring->length, format, args);
    }
    dstring->length += n;
    va_end(args);
    return n;
}

void dstring_clear(dstring_t *dstring) {
    dstring->capacity = DSTRING_INIT_CAPACITY;
    dstring->length = 0;
    free(dstring->data);
    dstring->data = malloc(dstring->capacity);
    dstring->data[0] = '\0';
}

void dstring_free(dstring_t *dstring) {
    free(dstring->data);
}