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

typedef struct {
        cache_entry_t* buckets[CACHE_BUCKET_COUNT];
        size_t bucket_lengths[CACHE_BUCKET_COUNT];
        cache_entry_t* most_recent;
        cache_entry_t* least_recent;
        size_t bytes;
} cache_state_t;

static pthread_key_t cache_state_key;
static pthread_once_t cache_key_once = PTHREAD_ONCE_INIT;
static int cache_key_status;
static _Thread_local cache_state_t* thread_cache;

#define CACHE_ENTRY_BUDGET (SANITIZEC_CACHE_MAX_BYTES - sizeof(cache_state_t))

static void destroy_cache_state(void* data) {
        cache_state_t* state = (cache_state_t*)data;
        if (!state) return;
        cache_entry_t* entry = state->most_recent;
        while (entry) {
                cache_entry_t* older = entry->older;
                free(entry);
                entry = older;
        }
        thread_cache = NULL;
        free(state);
}

static void create_cache_key(void) {
        cache_key_status =
            pthread_key_create(&cache_state_key, destroy_cache_state);
}

static cache_state_t* get_cache_state(void) {
        if (thread_cache) return thread_cache;
        if (pthread_once(&cache_key_once, create_cache_key) != 0 ||
            cache_key_status != 0)
                return NULL;
        cache_state_t* state = (cache_state_t*)calloc(1, sizeof(*state));
        if (!state) return NULL;
        if (pthread_setspecific(cache_state_key, state) != 0) {
                free(state);
                return NULL;
        }
        thread_cache = state;
        return state;
}

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

static void detach_entry(cache_state_t* state, cache_entry_t* entry) {
        if (entry->newer) {
                entry->newer->older = entry->older;
        } else {
                state->most_recent = entry->older;
        }

        if (entry->older) {
                entry->older->newer = entry->newer;
        } else {
                state->least_recent = entry->newer;
        }
}

static void mark_most_recent(cache_state_t* state, cache_entry_t* entry) {
        entry->newer = NULL;
        entry->older = state->most_recent;
        if (state->most_recent) {
                state->most_recent->newer = entry;
        } else {
                state->least_recent = entry;
        }
        state->most_recent = entry;
}

static void evict_least_recent(cache_state_t* state) {
        cache_entry_t* entry = state->least_recent;
        size_t bucket        = (size_t)(entry->hash % CACHE_BUCKET_COUNT);
        cache_entry_t** bucket_entry = &state->buckets[bucket];

        while (*bucket_entry != entry) {
                bucket_entry = &(*bucket_entry)->bucket_next;
        }
        *bucket_entry = entry->bucket_next;
        state->bucket_lengths[bucket]--;

        detach_entry(state, entry);
        state->bytes -= entry->allocation_size;
        free(entry);
}

char* sanitizec_cache_get(const char* input, size_t input_len, int ruleset) {
        if (!input || input_len > SANITIZEC_CACHE_MAX_INPUT_BYTES ||
            input_len > CACHE_ENTRY_BUDGET - sizeof(cache_entry_t) - 2) {
                return NULL;
        }
        cache_state_t* state = get_cache_state();
        if (!state) return NULL;
        uint64_t hash = hash_key(input, input_len, ruleset);
        size_t bucket = (size_t)(hash % CACHE_BUCKET_COUNT);

        for (cache_entry_t* entry = state->buckets[bucket]; entry;
             entry                = entry->bucket_next) {
                if (entry->hash == hash && entry->ruleset == ruleset &&
                    entry->input_len == input_len &&
                    memcmp(entry_input(entry), input, input_len) == 0) {
                        size_t output_len = entry->output_len;
                        char* output      = (char*)malloc(output_len + 1);
                        if (output) {
                                memcpy(output, entry_output(entry),
                                       output_len + 1);
                                detach_entry(state, entry);
                                mark_most_recent(state, entry);
                        }
                        return output;
                }
        }

        return NULL;
}

void sanitizec_cache_store(const char* input, size_t input_len, int ruleset,
                           const char* output, size_t output_len) {
        if (!input || !output) return;
        if (input_len > SANITIZEC_CACHE_MAX_INPUT_BYTES ||
            input_len > CACHE_ENTRY_BUDGET - sizeof(cache_entry_t) - 2) {
                return;
        }
        size_t remaining =
            CACHE_ENTRY_BUDGET - sizeof(cache_entry_t) - input_len - 2;
        if (output_len > remaining) return;
        cache_state_t* state = get_cache_state();
        if (!state) return;

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

        for (cache_entry_t* current = state->buckets[bucket]; current;
             current                = current->bucket_next) {
                if (current->hash == hash && current->ruleset == ruleset &&
                    current->input_len == input_len &&
                    memcmp(entry_input(current), input, input_len) == 0) {
                        detach_entry(state, current);
                        mark_most_recent(state, current);
                        free(entry);
                        return;
                }
        }

        if (state->bucket_lengths[bucket] >= CACHE_BUCKET_MAX_ENTRIES) {
                free(entry);
                return;
        }

        while (state->bytes > CACHE_ENTRY_BUDGET - allocation_size) {
                evict_least_recent(state);
        }
        entry->bucket_next     = state->buckets[bucket];
        state->buckets[bucket] = entry;
        state->bucket_lengths[bucket]++;
        mark_most_recent(state, entry);
        state->bytes += allocation_size;
}
