#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../sanitizec.h"// Assuming the main header file is one level up

/**
 * @brief Runs the SQL Safe test case using sanitizec_apply.
 * @return 1 on success, 0 on failure.
 */
int run_sql_safe_test(void) {
        // Test case combining all keywords (DML, PRAGMA, 1=1, SLEEP, CONCAT) in
        // mixed case.
        const char* input =
            "ID' OR 1=1 --;"
            "DROPtable; "
            "UNIon sELecT * from t;"
            "PRAGMA foreign_keys;"
            "Wait and SLEEP(5) seconds;"
            "UPDATE users;"
            "DELEte from logs;"
            "Concat(A, B)";

        // All keywords (1=1, DROP, UNION, SELECT, PRAGMA, SLEEP, UPDATE,
        // DELETE, CONCAT) are removed.
        const char* expected =
            "ID' OR  --;"          // 1=1 removed
            "table; "              // DROP removed
            "  * from t;"          // UNION, SELECT removed
            " foreign_keys;"       // PRAGMA removed
            "Wait and (5) seconds;"// SLEEP removed
            " users;"              // UPDATE removed
            " from logs;"          // DELETE removed
            "(A, B)";              // CONCAT removed

        char* errmsg      = NULL;
        char* safe_output = NULL;
        int success       = 0;

        printf("testing: [SQL Safe Filter - Command Removal]\n");
        printf("str: %s\n", input);

        // Assuming SANITIZEC_RULE_SQL_SAFE is defined in sanitizec.h
        // NOTE: You must use the actual enum constant for this rule in your
        // setup.
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
