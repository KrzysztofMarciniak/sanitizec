#include "sanitizec.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    // Input containing HTML tags, XSS payload, quotes, and ampersands
    const char* test_input_1 = "User Input: <script>alert('Hello & World!')</script> and \"quotes\"";
    char *errmsg = NULL;
    char *safe_output = NULL;

    printf("--- SanitizeC Test Program (XSS Escape Only) ---\n\n");
    printf("Input: %s\n", test_input_1);

    // Apply the only implemented rule: SANITIZEC_RULE_XSS_ESCAPE
    safe_output = sanitizec_apply(test_input_1, SANITIZEC_RULE_XSS_ESCAPE, &errmsg);

    if (safe_output) {
        printf("Output: %s\n", safe_output);
        free(safe_output);
    } else {
        // If sanitizec_apply fails, check and report the error message
        fprintf(stderr, "Sanitization failed!\n");
        if (errmsg) {
            fprintf(stderr, "Error Message: %s\n", errmsg);
            free(errmsg); // Free the allocated error string
        } else {
            fprintf(stderr, "Error Message: Unknown failure (returned NULL without setting errmsg).\n");
        }
    }

    printf("\n--- Test complete ---\n");

    return 0;
}
