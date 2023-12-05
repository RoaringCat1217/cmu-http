#include <string.h>

#include "file_dependency.h"


void graph_init(dependency_graph_t *graph) {
    graph->size = 0;
    graph->head = NULL;
    graph->nfiles = 0;
}

void graph_insert(dependency_graph_t *graph, const char *key, const char *value) {
    key_file_t *keynode;
    for (keynode = graph->head; keynode != NULL; keynode = keynode->next)
        if (strcmp(keynode->filename, key) == 0)
            break;
    if (keynode == NULL) {
        keynode = malloc(sizeof(key_file_t));
        strcpy(keynode->filename, key);
        keynode->values = NULL;
        keynode->next = graph->head;
        graph->head = keynode;
        graph->size++;
    }
    value_file_t *valnode = NULL;
    for (valnode = keynode->values; valnode != NULL; valnode = valnode->next)
        if (strcmp(valnode->filename, value) == 0)
            break;
    if (valnode == NULL) {
        valnode = malloc(sizeof(value_file_t));
        strcpy(valnode->filename, value);
        valnode->next = keynode->values;
        keynode->values = valnode;
        graph->nfiles++;
    }
}

key_file_t *graph_find(dependency_graph_t *graph, const char *key) {
    key_file_t *keynode = NULL;
    for (keynode = graph->head; keynode != NULL; keynode = keynode->next)
        if (strcmp(keynode->filename, key) == 0)
            break;
    return keynode;
}

void graph_free(dependency_graph_t *graph) {
    key_file_t *key = graph->head, *next_key;
    value_file_t *val, *next_val;
    while (key != NULL) {
        next_key = key->next;
        val = key->values;
        while (val != NULL) {
            next_val = val->next;
            free(val);
            val = next_val;
        }
        free(key);
        key = next_key;
    }
}