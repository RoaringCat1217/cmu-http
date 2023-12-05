#ifndef STR_QUEUE_H
#define STR_QUEUE_H

#include <stdlib.h>

typedef struct {
    size_t size;
    size_t capacity;
    size_t head;
    char **data;
} str_queue_t;

void str_queue_init(str_queue_t *queue);
void str_queue_push(str_queue_t *queue, const char *str);
char *str_queue_pop(str_queue_t *queue);
void str_queue_free(str_queue_t *queue);

#endif