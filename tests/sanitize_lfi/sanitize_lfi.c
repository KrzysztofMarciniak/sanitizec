#include "sanitize_lfi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sanitizec.h"

/**
 * @brief Runs the Local File Inclusion (LFI) test case using sanitizec_apply.
 * @return 1 on success, 0 on failure.
 */
int run_lfi_test(void) {
        const char* input    = "/etc/passwd/../../../../tmp/file.log";
        const char* expected = "/etc/passwd/tmp/file.log";// All "../" removed
        char* errmsg         = NULL;
        char* safe_output    = NULL;
        int success          = 0;

        printf("testing: [Local File Inclusion (LFI) Filter]\n");
        printf("str: %s\n", input);

        // Assuming SANITIZEC_RULE_LFI is defined in sanitizec.h
        // The actual constant value will depend on your enum definition.
        // For this example, we assume it's the next rule constant available.
        // NOTE: Replace SANITIZEC_RULE_LFI with the actual enum value if known.
        safe_output = sanitizec_apply(input, SANITIZEC_RULE_LFI, &errmsg);

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
