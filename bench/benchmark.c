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

static int run_case(const char* name, const char* input_template,
                    size_t input_len, int ruleset, size_t iterations,
                    int unique_inputs) {
        char* input = (char*)malloc(input_len + 1);
        if (!input) {
                fprintf(stderr, "%s: failed to allocate input buffer\n", name);
                return 1;
        }
        memcpy(input, input_template, input_len + 1);

        struct timespec start;
        struct timespec end;
        if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
                perror("clock_gettime");
                free(input);
                return 1;
        }

        uint64_t checksum = 0;
        for (size_t i = 0; i < iterations; i++) {
                if (unique_inputs) set_unique_prefix(input, i);

                char* errmsg = NULL;
                char* output = sanitizec_apply(input, ruleset, &errmsg);
                if (!output) {
                        fprintf(stderr, "%s: sanitizec_apply failed: %s\n",
                                name, errmsg ? errmsg : "unknown error");
                        free(errmsg);
                        free(input);
                        return 1;
                }
                checksum += (unsigned char)output[0];
                free(output);
                free(errmsg);
        }

        if (clock_gettime(CLOCK_MONOTONIC, &end) != 0) {
                perror("clock_gettime");
                free(input);
                return 1;
        }

        double elapsed = elapsed_seconds(start, end);
        double calls_per_second = (double)iterations / elapsed;
        double mebibytes_per_second =
            ((double)input_len * (double)iterations) /
            (elapsed * 1024.0 * 1024.0);

        printf("%-25s input=%7zu B  calls=%7zu  time=%8.3f ms  "
               "rate=%10.0f calls/s  input=%8.2f MiB/s  checksum=%" PRIu64
               "\n",
               name, input_len, iterations, elapsed * 1000.0,
               calls_per_second, mebibytes_per_second, checksum);
        free(input);
        return 0;
}

static char* make_long_input(size_t input_len) {
        static const char pattern[] =
            "A field/value?x=1&y=2 #tag% and some text ";
        const size_t pattern_len = sizeof(pattern) - 1;
        char* input = (char*)malloc(input_len + 1);
        if (!input) return NULL;

        for (size_t i = 0; i < input_len; i++) {
                input[i] = pattern[i % pattern_len];
        }
        input[input_len] = '\0';
        return input;
}

int main(void) {
        static const char short_xss[] =
            "Hello <strong>friend & team</strong>!";
        static const char short_url[] = "field=alice@example.com / a b";
        static const char filter_pattern[] =
            "This is a long alphanumeric filter input with 123 values. ";
        char* long_input = make_long_input(LONG_INPUT_BYTES);
        char* long_filter = make_long_input(LONG_INPUT_BYTES);
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

        printf("sanitizec benchmark: short and long, repeated and unique "
               "inputs\n");

        int failed = 0;
        failed |= run_case("short/repeated XSS", short_xss, sizeof(short_xss) - 1,
                           SANITIZEC_RULE_XSS_ESCAPE, SHORT_ITERATIONS, 0);
        failed |= run_case("short/unique URL", short_url, sizeof(short_url) - 1,
                           SANITIZEC_RULE_URL_COMPONENT_ENCODE,
                           SHORT_ITERATIONS, 1);
        failed |= run_case("long/repeated URL", long_input, LONG_INPUT_BYTES,
                           SANITIZEC_RULE_URL_COMPONENT_ENCODE, LONG_ITERATIONS,
                           0);
        failed |= run_case("long/unique URL", long_input, LONG_INPUT_BYTES,
                           SANITIZEC_RULE_URL_COMPONENT_ENCODE, LONG_ITERATIONS,
                           1);
        failed |= run_case(
            "long/repeated character filter", long_filter, LONG_INPUT_BYTES,
            SANITIZEC_RULE_ALPHANUMERIC_WITH_SPACES_ONLY, LONG_ITERATIONS, 0);

        free(long_input);
        free(long_filter);
        return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
