#include "trim_whitespace.h"// declares run_trim_whitespace_test

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sanitizec.h"// your main sanitization dispatcher

/**
 * @brief Runs the whitespace trimming test case.
 * * Compares the output of sanitizec_apply against a known correct output.
 * * @return 1 on success, 0 on failure.
 */
int run_trim_whitespace_test(void) {
        const char* input    = "  \t  Hello, World!  \n\n ";
        const char* expected = "Hello, World!";

        char* errmsg = NULL;
        char* output =
            sanitizec_apply(input, SANITIZEC_RULE_WHITESPACE_TRIM, &errmsg);
        int success = 0;

        printf("testing: [trim_whitespace]\n");
        printf("str: [%s]\n", input);

        if (!output) {
                printf("str sanitized : (NULL)\nfailure! (Error: %s)\n",
                       errmsg ? errmsg : "Unknown");
                fprintf(stderr, "Test FAILED: Sanitization returned NULL.\n");
                if (errmsg) free(errmsg);
                return 0;
        }

        printf("str sanitized : [%s]\n", output);

        if (strcmp(output, expected) == 0) {
                printf("success!\n");
                success = 1;
        } else {
                printf("failure! Output did not match expected.\n");
                fprintf(stderr, "Test FAILED: Output mismatch.\n");
                fprintf(stderr, "  Expected: [%s]\n", expected);
                fprintf(stderr, "  Actual:   [%s]\n", output);
        }

        free(output);
        return success;
}
