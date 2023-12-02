#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fileset.h"

static uint64_t hash(const char *string) {
    uint64_t result = 0;
    uint64_t acc = 0;
    int count = 0;
    size_t len = strlen(string);
    for (int i = 0; i < len; i++) {
        acc <<= 8;
        acc |= string[i];
        count++;
        if (count == 8) {
            result ^= acc;
            acc = 0;
            count = 0;
        }
    }
    result ^= acc;
    return result;
}

void fileset_init(fileset_t *fileset) {
    fileset->size = 0;
    for (int i = 0; i < N_BUCKETS; i++)
        fileset->buckets[i] = NULL;
}

bool fileset_insert(fileset_t *fileset, const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0)
        return false;
    file_entry_t *new_entry = malloc(sizeof(file_entry_t));
    new_entry->filename = malloc(strlen(filename) + 1);
    strcpy(new_entry->filename, filename);
    new_entry->fd = fd;
    new_entry->next = NULL;

    uint64_t hashval = hash(filename);
    int idx = hashval % N_BUCKETS;
    file_entry_t *entry = fileset->buckets[idx];
    if (entry == NULL)
        fileset->buckets[idx] = new_entry;
    else {
        while (entry->next != NULL)
            entry = entry->next;
        entry->next = new_entry;
    }
    fileset->size++;
    return true;
}

int fileset_find(fileset_t *fileset, const char *filename) {
    uint64_t hashval = hash(filename);
    int idx = hashval % N_BUCKETS;
    file_entry_t *entry = fileset->buckets[idx];
    for (; entry != NULL; entry = entry->next) {
        if (strcmp(filename, entry->filename) == 0)
            return entry->fd;
    }
    return -1;
}

void fileset_free(fileset_t *fileset) {
    for (int i = 0; i < N_BUCKETS; i++) {
        file_entry_t *entry = fileset->buckets[i], *next = NULL;
        while (entry != NULL) {
            next = entry->next;
            free(entry->filename);
            close(entry->fd);
            free(entry);
            entry = next;
        }
    }
}