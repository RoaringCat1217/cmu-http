#ifndef FILE_DEPENDENCY_H
#define FILE_DEPENDENCY_H

#define MAX_FILENAME 256

#include <stdlib.h>

typedef struct value_file {
    char filename[MAX_FILENAME];
    struct value_file *next;
} value_file_t;

typedef struct key_file {
    char filename[MAX_FILENAME];
    struct key_file *next;
    value_file_t *values;
} key_file_t;

typedef struct {
    key_file_t *head;
    size_t size;
    size_t nfiles;
} dependency_graph_t;

void graph_init(dependency_graph_t *graph);
void graph_insert(dependency_graph_t *graph, const char *key, const char *value);
key_file_t * graph_find(dependency_graph_t *graph, const char *key);
void graph_free(dependency_graph_t *graph);

#endif