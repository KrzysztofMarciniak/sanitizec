#include "numeric_only.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sanitizec.h"

/**
 * @brief Runs the numbers only test case using sanitizec_apply.
 * @return 1 on success, 0 on failure.
 */
int run_numeric_only_test(void) {
        const char* input    = "Account Number: 123-ABC-456-XYZ";
        const char* expected = "123456";
        char* errmsg         = NULL;
        char* safe_output    = NULL;
        int success          = 0;

        printf("testing: [Numbers only]\n");
        printf("str: %s\n", input);

        safe_output =
            sanitizec_apply(input, SANITIZEC_RULE_NUMERIC_ONLY, &errmsg);

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
