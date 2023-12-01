#include "vector.h"

void vector_init(vector_t *vector) {
    vector->capacity = VECTOR_INIT_CAPACITY;
    vector->size = 0;
    vector->data = (uint8_t *)malloc(vector->capacity);
}

void vector_push_back(vector_t *vector, const uint8_t *data, size_t size) {
    bool grow = false;
    while (vector->size + size > vector->capacity) {
        grow = true;
        vector->capacity *= 2;
    }
    if (grow)
        vector->data = realloc(vector->data, vector->capacity);
    memcpy(vector->data + vector->size, data, size);
    vector->size += size;
}

void vector_clear(vector_t *vector) {
    vector->size = 0;
    vector->capacity = VECTOR_INIT_CAPACITY;
    free(vector->data);
    vector->data = (uint8_t *)malloc(vector->capacity);
}

void vector_free(vector_t *vector) {
    free(vector->data);
}
