#include "email_allowed_chars.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sanitizec.h"

int run_email_allowed_chars_test(void) {
        const char* input    = "A_l%ice-tag+@EXAMPLE.com; evil!";
        const char* expected = "A_l%ice-tag+@EXAMPLE.comevil";
        char* errmsg         = NULL;
        char* safe_output =
            sanitizec_apply(input, SANITIZEC_RULE_EMAIL_ALLOWED_CHARS, &errmsg);
        int success = 0;

        printf("testing: [Email-address character allowlist]\n");
        if (!safe_output) {
                fprintf(stderr, "Test FAILED: Sanitization returned NULL: %s\n",
                        errmsg ? errmsg : "Unknown");
        } else if (strcmp(safe_output, expected) == 0) {
                printf("success!\n");
                success = 1;
        } else {
                fprintf(stderr, "Test FAILED: Output mismatch.\n");
                fprintf(stderr, "  Expected: %s\n", expected);
                fprintf(stderr, "  Actual:   %s\n", safe_output);
        }

        free(errmsg);
        free(safe_output);
        return success;
}
