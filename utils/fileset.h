#ifndef FILESET_H
#define FILESET_H

#include <stdbool.h>

#define N_BUCKETS 256
#define MAX_LINE 1024

typedef struct file_entry {
    char *filename;
    int fd;
    struct file_entry *next;
} file_entry_t;

typedef struct {
    file_entry_t *buckets[N_BUCKETS];
    char path[MAX_LINE];
    char root[MAX_LINE];
    size_t size;
} fileset_t;

void fileset_init(fileset_t *fileset, char *root);
bool fileset_insert(fileset_t *fileset, const char *filename,
                    const char *path_to_file);
int fileset_find(fileset_t *fileset, const char *filename);
void fileset_free(fileset_t *fileset);

#endif