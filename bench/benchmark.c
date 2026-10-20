#define _POSIX_C_SOURCE 200809L

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sanitizec.h"

#define SHORT_ITERATIONS 250000
#define LONG_ITERATIONS 32
#define LONG_INPUT_BYTES (256 * 1024)
#define BENCH_REPEATS 5

#ifdef SANITIZEC_ENABLE_CACHE
#define CACHE_STATUS "enabled"
#else
#define CACHE_STATUS "disabled"
#endif

static const char hex_digits[] = "0123456789abcdef";

static double elapsed_seconds(struct timespec start, struct timespec end) {
        return (double)(end.tv_sec - start.tv_sec) +
               (double)(end.tv_nsec - start.tv_nsec) / 1000000000.0;
}

static void set_unique_prefix(char* input, size_t value) {
        for (int i = 7; i >= 0; i--) {
                input[i] = hex_digits[value & 0x0F];
                value >>= 4;
        }
}

static int compare_times(const void* lhs, const void* rhs) {
        double left  = *(const double*)lhs;
        double right = *(const double*)rhs;
        return (left > right) - (left < right);
}

static int run_iterations(const char* name, char* input, int ruleset,
                          size_t iterations, int unique_inputs,
                          size_t* unique_value, uint64_t* checksum) {
        for (size_t i = 0; i < iterations; i++) {
                if (unique_inputs) set_unique_prefix(input, (*unique_value)++);
                char* errmsg = NULL;
                char* output = sanitizec_apply(input, ruleset, &errmsg);
                if (!output) {
                        fprintf(stderr, "%s: sanitizec_apply failed: %s\n",
                                name, errmsg ? errmsg : "unknown error");
                        free(errmsg);
                        return 1;
                }
                *checksum += (unsigned char)output[0];
                free(output);
                free(errmsg);
        }
        return 0;
}

static int run_case(const char* name, const char* input_template,
                    size_t input_len, int ruleset, size_t iterations,
                    int unique_inputs) {
        char* input = (char*)malloc(input_len + 1);
        if (!input) {
                fprintf(stderr, "%s: failed to allocate input buffer\n", name);
                return 1;
        }
        memcpy(input, input_template, input_len + 1);

        uint64_t checksum   = 0;
        size_t unique_value = 0;
        size_t warmup_calls = iterations / 10;
        double sample_seconds[BENCH_REPEATS];
        if (warmup_calls == 0) warmup_calls = 1;
        if (run_iterations(name, input, ruleset, warmup_calls, unique_inputs,
                           &unique_value, &checksum)) {
                free(input);
                return 1;
        }

        for (size_t repeat = 0; repeat < BENCH_REPEATS; repeat++) {
                struct timespec start;
                struct timespec end;
                if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
                        perror("clock_gettime");
                        free(input);
                        return 1;
                }
                if (run_iterations(name, input, ruleset, iterations,
                                   unique_inputs, &unique_value, &checksum)) {
                        free(input);
                        return 1;
                }
                if (clock_gettime(CLOCK_MONOTONIC, &end) != 0) {
                        perror("clock_gettime");
                        free(input);
                        return 1;
                }
                sample_seconds[repeat] = elapsed_seconds(start, end);
        }

        qsort(sample_seconds, BENCH_REPEATS, sizeof(sample_seconds[0]),
              compare_times);

        double elapsed              = sample_seconds[BENCH_REPEATS / 2];
        double calls_per_second     = (double)iterations / elapsed;
        double mebibytes_per_second = ((double)input_len * (double)iterations) /
                                      (elapsed * 1024.0 * 1024.0);

        printf(
            "%-25s input=%7zu B  calls=%7zu  median=%8.3f ms  "
            "samples=%d  "
            "rate=%10.0f calls/s  input=%8.2f MiB/s  checksum=%" PRIu64 "\n",
            name, input_len, iterations, elapsed * 1000.0, BENCH_REPEATS,
            calls_per_second, mebibytes_per_second, checksum);
        free(input);
        return 0;
}

static char* make_long_input(size_t input_len) {
        static const char pattern[] =
            "A field/value?x=1&y=2 #tag% and some text ";
        const size_t pattern_len = sizeof(pattern) - 1;
        char* input              = (char*)malloc(input_len + 1);
        if (!input) return NULL;

        for (size_t i = 0; i < input_len; i++) {
                input[i] = pattern[i % pattern_len];
        }
        input[input_len] = '\0';
        return input;
}

int main(void) {
        static const char short_xss[] = "Hello <strong>friend & team</strong>!";
        static const char clean_xss[] = "Hello friend and team.";
        static const char short_url[] = "field=alice@example.com / a b";
        static const char clean_url[] = "field=alice@example.com";
        static const char filter_pattern[] =
            "This is a long alphanumeric filter input with 123 values. ";
        static const char clean_filter[] = "Clean alphanumeric 123";
        static const char dirty_filter[] = "Clean, alphanumeric! 123?";
        static const char clean_sql[]    = "This query contains no tokens.";
        static const char dirty_sql[] =
            "SELECT name FROM users WHERE id=1;SLEEP(2)";
        static const char clean_shell[] =
            "Use the regular application console.";
        static const char dirty_shell[] =
            "nc -l -p 4444; bash -i; /dev/tcp/127.0.0.1";
        static const char clean_lfi[] = "/var/www/site/index.html";
        static const char dirty_lfi[] = "../../../etc/passwd";
        char* long_input              = make_long_input(LONG_INPUT_BYTES);
        char* long_filter             = make_long_input(LONG_INPUT_BYTES);
        if (!long_input || !long_filter) {
                fprintf(stderr, "Failed to allocate long benchmark inputs.\n");
                free(long_input);
                free(long_filter);
                return EXIT_FAILURE;
        }
        for (size_t i = 0; i < LONG_INPUT_BYTES; i++) {
                long_filter[i] =
                    filter_pattern[i % (sizeof(filter_pattern) - 1)];
        }

        printf(
            "sanitizec benchmark: short/long, clean/dirty, repeated/unique "
            "inputs; cache %s\n",
            CACHE_STATUS);

        int failed = 0;
        failed |=
            run_case("short/repeated XSS", short_xss, sizeof(short_xss) - 1,
                     SANITIZEC_RULE_XSS_ESCAPE, SHORT_ITERATIONS, 0);
        failed |= run_case("short/clean XSS", clean_xss, sizeof(clean_xss) - 1,
                           SANITIZEC_RULE_XSS_ESCAPE, SHORT_ITERATIONS, 0);
        failed |=
            run_case("short/unique URL", short_url, sizeof(short_url) - 1,
                     SANITIZEC_RULE_URL_COMPONENT_ENCODE, SHORT_ITERATIONS, 1);
        failed |=
            run_case("short/clean URL", clean_url, sizeof(clean_url) - 1,
                     SANITIZEC_RULE_URL_COMPONENT_ENCODE, SHORT_ITERATIONS, 0);
        failed |= run_case(
            "short/clean filter", clean_filter, sizeof(clean_filter) - 1,
            SANITIZEC_RULE_ALPHANUMERIC_WITH_SPACES_ONLY, SHORT_ITERATIONS, 0);
        failed |= run_case(
            "short/dirty filter", dirty_filter, sizeof(dirty_filter) - 1,
            SANITIZEC_RULE_ALPHANUMERIC_WITH_SPACES_ONLY, SHORT_ITERATIONS, 0);
        failed |= run_case("short/clean SQL", clean_sql, sizeof(clean_sql) - 1,
                           SANITIZEC_RULE_SQL, SHORT_ITERATIONS, 0);
        failed |= run_case("short/dirty SQL", dirty_sql, sizeof(dirty_sql) - 1,
                           SANITIZEC_RULE_SQL, SHORT_ITERATIONS, 0);
        failed |=
            run_case("short/clean shell", clean_shell, sizeof(clean_shell) - 1,
                     SANITIZEC_RULE_REVERSE_SHELL, SHORT_ITERATIONS, 0);
        failed |=
            run_case("short/dirty shell", dirty_shell, sizeof(dirty_shell) - 1,
                     SANITIZEC_RULE_REVERSE_SHELL, SHORT_ITERATIONS, 0);
        failed |= run_case("short/clean LFI", clean_lfi, sizeof(clean_lfi) - 1,
                           SANITIZEC_RULE_LFI, SHORT_ITERATIONS, 0);
        failed |= run_case("short/dirty LFI", dirty_lfi, sizeof(dirty_lfi) - 1,
                           SANITIZEC_RULE_LFI, SHORT_ITERATIONS, 0);
        failed |=
            run_case("long/repeated URL", long_input, LONG_INPUT_BYTES,
                     SANITIZEC_RULE_URL_COMPONENT_ENCODE, LONG_ITERATIONS, 0);
        failed |=
            run_case("long/unique URL", long_input, LONG_INPUT_BYTES,
                     SANITIZEC_RULE_URL_COMPONENT_ENCODE, LONG_ITERATIONS, 1);
        failed |= run_case(
            "long/repeated character filter", long_filter, LONG_INPUT_BYTES,
            SANITIZEC_RULE_ALPHANUMERIC_WITH_SPACES_ONLY, LONG_ITERATIONS, 0);

        free(long_input);
        free(long_filter);
        return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
