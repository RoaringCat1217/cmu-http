#ifndef VECTOR_H
#define VECTOR_H

#include <stdint.h>
#include <stdlib.h>

#define VECTOR_INIT_CAPACITY 16;

typedef struct {
    size_t size;
    size_t capacity;
    uint8_t *data;
} vector_t;

void vector_init(vector_t *vector);
void vector_push_back(vector_t *vector, const uint8_t *data, size_t size);
void vector_pop_front(vector_t *vector, size_t size);
void vector_clear(vector_t *vector);
void vector_free(vector_t *vector);

#endif