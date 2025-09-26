#include "escape_xss.h" // Includes the declaration for run_xss_escape_test
#include "sanitizec.h"  // Your main library header
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Runs the basic XSS escape test case.
 * * Compares the output of sanitizec_apply against a known good string.
 * Prints the results in the requested format.
 * * @return 1 on success, 0 on failure.
 */
int run_xss_escape_test(void)
{
    // 1. Arrange: Define the input and the expected output
    const char *input = "User Input: <script>alert('Hello & World!')</script> and \"quotes\"";
    const char *expected = "User Input: &lt;script&gt;alert(&#39;Hello &amp; World!&#39;)&lt;/script&gt; and &quot;quotes&quot;";

    char *errmsg = NULL;
    char *safe_output = NULL;
    int success = 0;

    printf("testing: [escape_xss]\n");
    printf("str: %s\n", input);

    // 2. Act: Call the function under test
    safe_output = sanitizec_apply(input, SANITIZEC_RULE_XSS_ESCAPE, &errmsg);

    // 3. Assert & Cleanup

    // Check for NULL return (internal error)
    if (safe_output == NULL) {
        printf("str sanitized : (NULL)\nfailure! (Error: %s)\n", errmsg ? errmsg : "Unknown");
        fprintf(stderr, "Test FAILED: Sanitization returned NULL.\n");
        if (errmsg) free(errmsg);
        return 0; // Failure
    }

    printf("str sanitized : %s\n", safe_output);

    // Check if the actual output matches the expected output string
    if (strcmp(safe_output, expected) == 0) {
        printf("success!\n");
        success = 1;
    } else {
        printf("failure! Output did not match expected.\n");
        fprintf(stderr, "Test FAILED: Output mismatch.\n");
        fprintf(stderr, "  Expected: %s\n", expected);
        fprintf(stderr, "  Actual:   %s\n", safe_output);
    }

    // Final cleanup: Free the dynamically allocated output string
    free(safe_output);

    return success; // Return 1 (Success) or 0 (Failure)
}
