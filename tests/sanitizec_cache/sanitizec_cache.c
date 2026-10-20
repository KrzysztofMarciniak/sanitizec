#include "sanitizec_cache.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "misc/sanitizec_cache.h"
#include "sanitizec.h"

enum { CACHE_TEST_THREADS = 4, CACHE_TEST_ITERATIONS = 2000 };

typedef struct {
        const char* input;
        const char* expected;
        int success;
} worker_args_t;

static void* run_cache_worker(void* data) {
        worker_args_t* args = (worker_args_t*)data;
        args->success       = 1;

        for (int i = 0; i < CACHE_TEST_ITERATIONS; i++) {
                char* errmsg = NULL;
                char* output = sanitizec_apply(
                    args->input, SANITIZEC_RULE_URL_COMPONENT_ENCODE, &errmsg);
                if (!output || strcmp(output, args->expected) != 0) {
                        args->success = 0;
                        free(output);
                        free(errmsg);
                        return NULL;
                }
                free(output);
                free(errmsg);
        }

        return NULL;
}

static char* make_large_key(size_t size, char prefix) {
        char* key = (char*)malloc(size + 1);
        if (!key) return NULL;
        memset(key, 'a', size);
        key[0]    = prefix;
        key[size] = '\0';
        return key;
}

int run_sanitizec_cache_test(void) {
        int success     = 0;
        char* first     = NULL;
        char* second    = NULL;
        char* third     = NULL;
        char* oversized = NULL;
        char* output    = NULL;
        pthread_t threads[CACHE_TEST_THREADS];
        worker_args_t args[CACHE_TEST_THREADS];
        int threads_started = 0;

        printf("testing: [Sanitize cache]\n");

        sanitizec_cache_store("cache-test-hit", 101, "cached result");
        output = sanitizec_cache_get("cache-test-hit", 101);
        if (!output || strcmp(output, "cached result") != 0) {
                fprintf(stderr, "Test FAILED: Cache hit/miss behavior.\n");
                goto cleanup;
        }
        free(output);
        output = NULL;
        output = sanitizec_cache_get("cache-test-miss", 101);
        if (output != NULL) {
                fprintf(stderr, "Test FAILED: Cache miss behavior.\n");
                goto cleanup;
        }

        first  = make_large_key(400 * 1024, '1');
        second = make_large_key(400 * 1024, '2');
        third  = make_large_key(400 * 1024, '3');
        if (!first || !second || !third) {
                fprintf(stderr,
                        "Test FAILED: Could not allocate cache keys.\n");
                goto cleanup;
        }

        sanitizec_cache_store(first, 201, "one");
        sanitizec_cache_store(second, 202, "two");
        output = sanitizec_cache_get(first, 201);
        if (!output || strcmp(output, "one") != 0) {
                fprintf(stderr, "Test FAILED: Cache hit before eviction.\n");
                goto cleanup;
        }
        free(output);
        output = NULL;

        sanitizec_cache_store(third, 203, "three");
        output = sanitizec_cache_get(second, 202);
        if (output != NULL) {
                fprintf(stderr, "Test FAILED: LRU capacity eviction.\n");
                goto cleanup;
        }
        output = sanitizec_cache_get(first, 201);
        if (!output || strcmp(output, "one") != 0) {
                fprintf(stderr,
                        "Test FAILED: Recently used entry was evicted.\n");
                goto cleanup;
        }
        free(output);
        output = NULL;
        output = sanitizec_cache_get(third, 203);
        if (!output || strcmp(output, "three") != 0) {
                fprintf(stderr, "Test FAILED: New cache entry was evicted.\n");
                goto cleanup;
        }
        free(output);
        output = NULL;

        oversized = make_large_key(SANITIZEC_CACHE_MAX_BYTES, 'x');
        if (!oversized) {
                fprintf(
                    stderr,
                    "Test FAILED: Could not allocate oversized cache key.\n");
                goto cleanup;
        }
        sanitizec_cache_store(oversized, 204, "too large");
        output = sanitizec_cache_get(oversized, 204);
        if (output != NULL) {
                fprintf(stderr, "Test FAILED: Oversized entry was cached.\n");
                goto cleanup;
        }

        const char* thread_input    = "cache hit / thread test";
        const char* thread_expected = "cache%20hit%20%2F%20thread%20test";
        output = sanitizec_apply(thread_input,
                                 SANITIZEC_RULE_URL_COMPONENT_ENCODE, NULL);
        if (!output || strcmp(output, thread_expected) != 0) {
                fprintf(stderr, "Test FAILED: Cache integration setup.\n");
                goto cleanup;
        }
        free(output);
        output = NULL;

        for (int i = 0; i < CACHE_TEST_THREADS; i++) {
                args[i].input    = thread_input;
                args[i].expected = thread_expected;
                args[i].success  = 0;
                if (pthread_create(&threads[i], NULL, run_cache_worker,
                                   &args[i]) != 0) {
                        fprintf(stderr, "Test FAILED: pthread_create.\n");
                        goto cleanup;
                }
                threads_started++;
        }

        int join_failed = 0;
        for (int i = 0; i < threads_started; i++) {
                if (pthread_join(threads[i], NULL) != 0) {
                        join_failed = 1;
                }
        }
        threads_started = 0;
        if (join_failed) {
                fprintf(stderr, "Test FAILED: pthread_join.\n");
                goto cleanup;
        }

        for (int i = 0; i < CACHE_TEST_THREADS; i++) {
                if (!args[i].success) {
                        fprintf(stderr,
                                "Test FAILED: Concurrent cache result.\n");
                        goto cleanup;
                }
        }

        printf("success!\n");
        success = 1;

cleanup:
        for (int i = 0; i < threads_started; i++) {
                pthread_join(threads[i], NULL);
        }
        free(first);
        free(second);
        free(third);
        free(oversized);
        free(output);
        return success;
}
