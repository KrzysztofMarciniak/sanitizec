#include "alphanumeric_with_spaces_only.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sanitizec.h"

/**
 * @brief Conducts alphanumeric with spaces sanitization test.
 *
 * This test validates the sanitization library's ability to:
 * - Remove non-alphanumeric and non-space characters
 * - Preserve letters, numbers, and spaces
 * - Handle mixed input with special characters and punctuation
 *
 * @return int 1 if sanitization test passes, 0 if it fails
 */
int run_alphanumeric_with_spaces_test(void) {
        const char* input    = "Hello, World! This is a test string 123.";
        const char* expected = "Hello World This is a test string 123";
        char* errmsg         = NULL;
        char* safe_output    = NULL;
        int success          = 0;

        printf("testing: [Alphanumeric and Spaces Only]\n");
        printf("str: %s\n", input);

        safe_output = sanitizec_apply(
            input, SANITIZEC_RULE_ALPHANUMERIC_WITH_SPACES_ONLY, &errmsg);

        if (safe_output == NULL) {
                printf("str sanitized : (NULL)\nfailure! (Error: %s)\n",
                       errmsg ? errmsg : "Unknown");
                fprintf(stderr, "Test FAILED: Sanitization returned NULL.\n");
                if (errmsg) free(errmsg);
                return 0;
        }

        printf("str sanitized : %s\n", safe_output);

        if (strcmp(safe_output, expected) == 0) {
                printf("success!\n");
                success = 1;
        } else {
                printf("failure! Output did not match expected.\n");
                fprintf(stderr, "Test FAILED: Output mismatch.\n");
                fprintf(stderr, "  Expected: %s\n", expected);
                fprintf(stderr, "  Actual:   %s\n", safe_output);
        }

        free(safe_output);
        return success;
}
