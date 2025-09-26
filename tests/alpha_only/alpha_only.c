#include "alpha_only.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sanitizec.h"

/**
 * @brief Runs the alphabetic letters only test case using sanitizec_apply.
 * @return 1 on success, 0 on failure.
 */
int run_alpha_only_test(void) {
        const char *input    = "Hello World! 123 is a great 😃day.";
        const char *expected = "HelloWorldisagreatday";
        char *errmsg         = NULL;
        char *safe_output    = NULL;
        int success          = 0;

        printf("testing: [Alphabetic letters only]\n");
        printf("str: %s\n", input);

        safe_output = sanitizec_apply(input, SANITIZEC_RULE_ALPHA_ONLY, &errmsg);

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
