#include <string.h>
#include "str_queue.h"

#define QUEUE_INIT_CAPACITY 16

void str_queue_init(str_queue_t *queue) {
    queue->size = 0;
    queue->head = 0;
    queue->capacity = QUEUE_INIT_CAPACITY;
    queue->data = malloc(queue->capacity * sizeof(char *));
}

void str_queue_push(str_queue_t *queue, const char *str) {
    if (queue->size + 1 > queue->capacity) {
        char **new = malloc(queue->capacity * 2 * sizeof(char *));
        size_t rptr = queue->head, wptr = 0;
        for (size_t i = 0; i < queue->size; i++) {
            new[wptr] = queue->data[rptr];
            wptr++;
            rptr++;
            if (rptr >= queue->capacity)
                rptr -= queue->capacity;
        }
        free(queue->data);
        queue->capacity *= 2;
        queue->head = 0;
        queue->data = new;
    }
    size_t len = strlen(str);
    char *copy = malloc(len + 1);
    strcpy(copy, str);
    size_t tail = queue->head + queue->size;
    if (tail >= queue->capacity)
        tail -= queue->capacity;
    queue->data[tail] = copy;
    queue->size++;
}

char *str_queue_pop(str_queue_t *queue) {
    if (queue->size == 0)
        return NULL;
    char *pop = queue->data[queue->head];
    queue->head++;
    if (queue->head >= queue->capacity)
        queue->head -= queue->capacity;
    queue->size--;
    return pop;
}

void str_queue_free(str_queue_t *queue) {
    char *pop = NULL;
    while (queue->size > 0) {
        pop = str_queue_pop(queue);
        free(pop);
    }
    free(queue->data);
}