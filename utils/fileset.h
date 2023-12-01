#ifndef FILESET_H
#define FILESET_H

#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

#define N_BUCKETS 256

typedef struct file_entry {
    char *filename;
    int fd;
    struct file_entry *next;
} file_entry_t;

typedef struct {
    file_entry_t *buckets[N_BUCKETS];
    size_t size;
} fileset_t;

void fileset_init(fileset_t *fileset);
bool fileset_insert(fileset_t *fileset, const char *filename);
int fileset_find(fileset_t *fileset, const char *filename);
void fileset_free(fileset_t *fileset);

#endif