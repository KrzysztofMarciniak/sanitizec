#include "alphanumeric_with_underscore_hyphen_only.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sanitizec.h"

int run_alphanumeric_with_underscore_hyphen_only_test(void) {
        const char* input    = "User_Name-123! good-é";
        const char* expected = "User_Name-123good-";
        char* errmsg         = NULL;
        char* safe_output    = sanitizec_apply(
            input, SANITIZEC_RULE_ALPHANUMERIC_WITH_UNDERSCORE_HYPHEN_ONLY,
            &errmsg);
        int success = 0;

        printf("testing: [Alphanumeric, underscore, and hyphen only]\n");
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
