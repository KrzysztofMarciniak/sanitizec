#include "sanitize_lfi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sanitizec.h"

/**
 * @brief Conducts Local File Inclusion (LFI) sanitization test.
 *
 * This test validates the sanitization library's ability to:
 * - Remove directory traversal attempts (../)
 * - Prevent potential path manipulation attacks
 * - Sanitize file path inputs to mitigate LFI vulnerabilities
 *
 * @return int 1 if sanitization test passes, 0 if it fails
 */
int run_lfi_test(void) {
        const char* input    = "/etc/passwd/../../../../tmp/file.log";
        const char* expected = "/etc/passwd/tmp/file.log";
        char* errmsg         = NULL;
        char* safe_output    = NULL;
        int success          = 0;

        printf("testing: [Local File Inclusion (LFI) Filter]\n");
        printf("str: %s\n", input);

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
