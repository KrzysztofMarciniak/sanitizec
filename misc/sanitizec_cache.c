#include "sanitizec_cache.h"

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CACHE_BUCKET_COUNT 1024
#define CACHE_BUCKET_MAX_ENTRIES 8

typedef struct cache_entry {
        struct cache_entry* newer;
        struct cache_entry* older;
        struct cache_entry* bucket_next;
        size_t allocation_size;
        size_t input_len;
        size_t output_len;
        uint64_t hash;
        int ruleset;
        char data[];
} cache_entry_t;

static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static cache_entry_t* cache_buckets[CACHE_BUCKET_COUNT];
static size_t cache_bucket_lengths[CACHE_BUCKET_COUNT];
static cache_entry_t* most_recent;
static cache_entry_t* least_recent;
static size_t cache_bytes;

#define CACHE_ENTRY_BUDGET                                    \
        (SANITIZEC_CACHE_MAX_BYTES - sizeof(cache_buckets) -  \
         sizeof(cache_bucket_lengths) - sizeof(cache_mutex) - \
         sizeof(most_recent) - sizeof(least_recent) - sizeof(cache_bytes))

static uint64_t hash_key(const char* input, size_t input_len, int ruleset) {
        uint64_t hash = UINT64_C(14695981039346656037);
        uint32_t key  = (uint32_t)ruleset;

        for (size_t i = 0; i < sizeof(key); i++) {
                hash ^= (unsigned char)(key >> (i * 8));
                hash *= UINT64_C(1099511628211);
        }
        for (size_t i = 0; i < input_len; i++) {
                hash ^= (unsigned char)input[i];
                hash *= UINT64_C(1099511628211);
        }
        hash ^= hash >> 33;
        hash *= UINT64_C(0xff51afd7ed558ccd);
        hash ^= hash >> 33;
        return hash;
}

static const char* entry_input(const cache_entry_t* entry) {
        return entry->data;
}

static const char* entry_output(const cache_entry_t* entry) {
        return entry->data + entry->input_len + 1;
}

static void detach_entry(cache_entry_t* entry) {
        if (entry->newer) {
                entry->newer->older = entry->older;
        } else {
                most_recent = entry->older;
        }

        if (entry->older) {
                entry->older->newer = entry->newer;
        } else {
                least_recent = entry->newer;
        }
}

static void mark_most_recent(cache_entry_t* entry) {
        entry->newer = NULL;
        entry->older = most_recent;
        if (most_recent) {
                most_recent->newer = entry;
        } else {
                least_recent = entry;
        }
        most_recent = entry;
}

static void evict_least_recent(void) {
        cache_entry_t* entry = least_recent;
        size_t bucket        = (size_t)(entry->hash % CACHE_BUCKET_COUNT);
        cache_entry_t** bucket_entry = &cache_buckets[bucket];

        while (*bucket_entry != entry) {
                bucket_entry = &(*bucket_entry)->bucket_next;
        }
        *bucket_entry = entry->bucket_next;
        cache_bucket_lengths[bucket]--;

        detach_entry(entry);
        cache_bytes -= entry->allocation_size;
        free(entry);
}

char* sanitizec_cache_get(const char* input, int ruleset) {
        if (!input) return NULL;

        size_t input_len = strlen(input);
        if (input_len > CACHE_ENTRY_BUDGET - sizeof(cache_entry_t) - 2) {
                return NULL;
        }
        uint64_t hash = hash_key(input, input_len, ruleset);
        size_t bucket = (size_t)(hash % CACHE_BUCKET_COUNT);
        if (pthread_mutex_lock(&cache_mutex) != 0) return NULL;

        for (cache_entry_t* entry = cache_buckets[bucket]; entry;
             entry                = entry->bucket_next) {
                if (entry->hash == hash && entry->ruleset == ruleset &&
                    entry->input_len == input_len &&
                    memcmp(entry_input(entry), input, input_len) == 0) {
                        size_t output_len = entry->output_len;
                        char* output      = (char*)malloc(output_len + 1);
                        if (output) {
                                memcpy(output, entry_output(entry),
                                       output_len + 1);
                                detach_entry(entry);
                                mark_most_recent(entry);
                        }
                        pthread_mutex_unlock(&cache_mutex);
                        return output;
                }
        }

        pthread_mutex_unlock(&cache_mutex);
        return NULL;
}

void sanitizec_cache_store(const char* input, int ruleset, const char* output) {
        if (!input || !output) return;

        size_t input_len  = strlen(input);
        size_t output_len = strlen(output);
        if (input_len > CACHE_ENTRY_BUDGET - sizeof(cache_entry_t) - 2) {
                return;
        }
        size_t remaining =
            CACHE_ENTRY_BUDGET - sizeof(cache_entry_t) - input_len - 2;
        if (output_len > remaining) return;

        size_t allocation_size =
            sizeof(cache_entry_t) + input_len + 1 + output_len + 1;
        uint64_t hash        = hash_key(input, input_len, ruleset);
        size_t bucket        = (size_t)(hash % CACHE_BUCKET_COUNT);
        cache_entry_t* entry = (cache_entry_t*)malloc(allocation_size);
        if (!entry) return;

        entry->allocation_size = allocation_size;
        entry->input_len       = input_len;
        entry->output_len      = output_len;
        entry->hash            = hash;
        entry->ruleset         = ruleset;
        memcpy(entry->data, input, input_len + 1);
        memcpy(entry->data + input_len + 1, output, output_len + 1);

        if (pthread_mutex_lock(&cache_mutex) != 0) {
                free(entry);
                return;
        }

        for (cache_entry_t* current = cache_buckets[bucket]; current;
             current                = current->bucket_next) {
                if (current->hash == hash && current->ruleset == ruleset &&
                    current->input_len == input_len &&
                    memcmp(entry_input(current), input, input_len) == 0) {
                        detach_entry(current);
                        mark_most_recent(current);
                        pthread_mutex_unlock(&cache_mutex);
                        free(entry);
                        return;
                }
        }

        if (cache_bucket_lengths[bucket] >= CACHE_BUCKET_MAX_ENTRIES) {
                pthread_mutex_unlock(&cache_mutex);
                free(entry);
                return;
        }

        while (cache_bytes > CACHE_ENTRY_BUDGET - allocation_size) {
                evict_least_recent();
        }
        entry->bucket_next    = cache_buckets[bucket];
        cache_buckets[bucket] = entry;
        cache_bucket_lengths[bucket]++;
        mark_most_recent(entry);
        cache_bytes += allocation_size;
        pthread_mutex_unlock(&cache_mutex);
}
