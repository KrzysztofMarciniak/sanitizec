#include "sanitizec_buffer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "misc/sanitizec_buffer.h"
#include "sanitizec.h"

static int check_output(const char* input, int ruleset, const char* expected) {
        char* errmsg = NULL;
        char* output = sanitizec_apply(input, ruleset, &errmsg);
        int success = output && strcmp(output, expected) == 0;
        if (!success) {
                fprintf(stderr,
                        "Test FAILED: Expected \"%s\", got \"%s\" (%s).\n",
                        expected, output ? output : "(null)",
                        errmsg ? errmsg : "no error");
        }
        free(output);
        free(errmsg);
        return success;
}

int run_sanitizec_buffer_test(void) {
        printf("testing: [Stack-backed scratch buffers]\n");

        sanitizec_buffer_t buffer;
        sanitizec_buffer_init(&buffer);
        if (buffer.data != buffer.inline_data ||
            buffer.capacity != SANITIZEC_BUFFER_INLINE_CAPACITY) {
                fprintf(stderr, "Test FAILED: Inline buffer initialization.\n");
                sanitizec_buffer_destroy(&buffer);
                return 0;
        }

        buffer.data[0] = 'x';
        if (!sanitizec_buffer_set_length(&buffer, 1) ||
            !sanitizec_buffer_reserve(
                &buffer, SANITIZEC_BUFFER_INLINE_CAPACITY + 1) ||
            buffer.data == buffer.inline_data || buffer.data[0] != 'x' ||
            buffer.capacity < SANITIZEC_BUFFER_INLINE_CAPACITY + 1) {
                fprintf(stderr, "Test FAILED: Heap spill or data preservation.\n");
                sanitizec_buffer_destroy(&buffer);
                return 0;
        }
        sanitizec_buffer_destroy(&buffer);

        if (!check_output("<", SANITIZEC_RULE_XSS_ESCAPE |
                                   SANITIZEC_RULE_URL_COMPONENT_ENCODE,
                          "%26lt%3B") ||
            !check_output("", SANITIZEC_RULE_WHITESPACE_TRIM |
                                  SANITIZEC_RULE_URL_COMPONENT_ENCODE,
                          "") ||
            !check_output("unchanged", SANITIZEC_RULE_NONE, "unchanged")) {
                return 0;
        }

        char input[513];
        char expected[1537];
        memset(input, ' ', sizeof(input) - 1);
        input[sizeof(input) - 1] = '\0';
        for (size_t i = 0; i < sizeof(expected) - 1; i += 3) {
                memcpy(expected + i, "%20", 3);
        }
        expected[sizeof(expected) - 1] = '\0';
        if (!check_output(input, SANITIZEC_RULE_URL_COMPONENT_ENCODE,
                          expected)) {
                fprintf(stderr,
                        "Test FAILED: Expanded output should spill to heap.\n");
                return 0;
        }
        if (!check_output(input, SANITIZEC_RULE_URL_COMPONENT_ENCODE |
                                    SANITIZEC_RULE_ASCII_PRINTABLE_ONLY,
                          expected)) {
                fprintf(stderr,
                        "Test FAILED: Chained heap-spilled output.\n");
                return 0;
        }

        printf("success!\n");
        return 1;
}
