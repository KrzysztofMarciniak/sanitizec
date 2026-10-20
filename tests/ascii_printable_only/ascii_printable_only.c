#include "ascii_printable_only.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sanitizec.h"

int run_ascii_printable_only_test(void) {
        const char* input =
            "A\tB\nC\x7f"
            "D \xC3\xA9~";
        const char* expected = "ABCD ~";
        char* errmsg         = NULL;
        char* safe_output    = sanitizec_apply(
            input, SANITIZEC_RULE_ASCII_PRINTABLE_ONLY, &errmsg);
        int success = 0;

        printf("testing: [Printable ASCII only]\n");
        if (!safe_output) {
                fprintf(stderr, "Test FAILED: Sanitization returned NULL: %s\n",
                        errmsg ? errmsg : "Unknown");
        } else if (strcmp(safe_output, expected) == 0) {
                printf("success!\n");
                success = 1;
        } else {
                fprintf(stderr, "Test FAILED: Output mismatch.\n");
                fprintf(stderr, "  Expected: %s\n", expected);
                fprintf(stderr, "  Actual:   %s\n", safe_output);
        }

        free(errmsg);
        free(safe_output);
        return success;
}
