#ifndef VECTOR_H
#define VECTOR_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define VECTOR_INIT_CAPACITY 16;

typedef struct {
    size_t size;
    size_t capacity;
    uint8_t *data;
} vector_t;

void vector_init(vector_t *vector);
void vector_push_back(vector_t *vector, const uint8_t *data, size_t size);
void vector_clear(vector_t *vector);
void vector_free(vector_t *vector);

#endif