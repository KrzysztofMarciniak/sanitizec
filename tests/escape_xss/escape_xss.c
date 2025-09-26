#include "escape_xss.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sanitizec.h"

/**
 * @brief Conducts Cross-Site Scripting (XSS) escaping sanitization test.
 *
 * This test validates the sanitization library's ability to:
 * - Escape HTML special characters
 * - Convert potentially dangerous characters to their HTML entity equivalents
 * - Prevent XSS injection attempts through input sanitization
 *
 * @return int 1 if sanitization test passes, 0 if it fails
 */
int run_xss_escape_test(void) {
        const char* input =
            "User Input: <script>alert('Hello & World!')</script> and "
            "\"quotes\"";
        const char* expected =
            "User Input: &lt;script&gt;alert(&#39;Hello &amp; "
            "World!&#39;)&lt;/script&gt; and &quot;quotes&quot;";

        char* errmsg      = NULL;
        char* safe_output = NULL;
        int success       = 0;

        printf("testing: [escape_xss]\n");
        printf("str: %s\n", input);

        safe_output =
            sanitizec_apply(input, SANITIZEC_RULE_XSS_ESCAPE, &errmsg);

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
