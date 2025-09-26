#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../sanitizec.h"

/**
 * @brief Conducts comprehensive SQL injection sanitization test.
 *
 * This test validates the sanitization library's ability to:
 * - Remove SQL injection keywords and patterns
 * - Handle mixed-case SQL injection attempts
 * - Strip potentially dangerous SQL commands
 *
 * @return int 1 if all sanitization tests pass, 0 if any test fails
 */
int run_sql_safe_test(void) {
        const char* input =
            "ID' OR 1=1 --;"
            "DROPtable; "
            "UNIon sELecT * from t;"
            "PRAGMA foreign_keys;"
            "Wait and SLEEP(5) seconds;"
            "UPDATE users;"
            "DELEte from logs;"
            "Concat(A, B)";

        const char* expected =
            "ID' OR  --;"
            "table; "
            "  * from t;"
            " foreign_keys;"
            "Wait and (5) seconds;"
            " users;"
            " from logs;"
            "(A, B)";

        char* errmsg      = NULL;
        char* safe_output = NULL;
        int success       = 0;

        printf("testing: [SQL Safe Filter - Command Removal]\n");
        printf("str: %s\n", input);

        safe_output = sanitizec_apply(input, SANITIZEC_RULE_SQL, &errmsg);

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
