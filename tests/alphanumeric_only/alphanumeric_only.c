#include "alphanumeric_only.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sanitizec.h"

/**
 * @brief Conducts alphanumeric sanitization test.
 *
 * This test validates the sanitization library's ability to:
 * - Remove non-alphanumeric characters
 * - Preserve letters and numbers
 * - Handle mixed input with special characters, spaces, and punctuation
 *
 * @return int 1 if sanitization test passes, 0 if it fails
 */
int run_alphanumeric_only_test(void) {
        const char* input    = "User-Name: JohnDoe_123!";
        const char* expected = "UserNameJohnDoe123";
        char* errmsg         = NULL;
        char* safe_output    = NULL;
        int success          = 0;

        printf("testing: [Letters and Numbers only]\n");
        printf("str: %s\n", input);

        safe_output =
            sanitizec_apply(input, SANITIZEC_RULE_ALPHANUMERIC_ONLY, &errmsg);

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
