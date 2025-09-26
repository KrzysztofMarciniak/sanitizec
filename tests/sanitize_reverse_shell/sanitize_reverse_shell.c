#include "sanitize_reverse_shell.h"

#include <sanitizec.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Runs the Reverse Shell Safe test case using sanitizec_apply.
 * @return 1 on success, 0 on failure.
 */
int run_reverse_shell_safe_test(void) {
        // Revised Test Case to test IP pattern removal (127.0.0.1
        // and 10.1.1.255) and all other blacklisted patterns.
        const char* input_revised =
            "nc -l -p 4444 &"
            "BASH -i > /DEV/TCP/127.0.0.1/4444 0>&1"// IP removal test
            "BUSYBOX sh -c 'mkfifo /tmp/pipe'"
            "socket = new Socket(host, port)"
            "UserID=1 & password=1"
            "TEST: sh *sh"
            "10.1.1.255:80"                            // IP removal test
            "200.200.200.200-END"                      // IP removal test
            "This is not an IP 123.4. but 1.1.1.1 is.";// Partial IP and valid
                                                       // IP test

        const char* expected_revised =
            " -l -p 4444 "  // nc, & removed
            " -i > 4444 0>1"// BASH, dev, TCP, & removed. 127.0.0.1, / removed.
            "  -c ' pipe'"  // BUSYBOX, sh, mkfifo, / , tmp removed
            " = new (host, port)"               // socket removed
            "UserID=1  password=1"              // & removed
            "TEST:  *"                          // sh, *sh removed
            ":80"                               // 10.1.1.255 removed
            "-END"                              // 200.200.200.200 removed
            "This is not an IP 123.4. but  is.";// 1.1.1.1 removed

        char* errmsg      = NULL;
        char* safe_output = NULL;
        int success       = 0;

        printf(
            "testing: [Reverse Shell Filter - Command, Metacharacter, and IP "
            "Removal]\n");
        printf("str: %s\n", input_revised);

        safe_output = sanitizec_apply(input_revised,
                                      SANITIZEC_RULE_REVERSE_SHELL, &errmsg);

        if (safe_output == NULL) {
                printf("str sanitized : (NULL)\nfailure! (Error: %s)\n",
                       errmsg ? errmsg : "Unknown");
                fprintf(stderr, "Test FAILED: Sanitization returned NULL.\n");
                if (errmsg) free(errmsg);
                return 0;
        }

        printf("str sanitized : %s\n", safe_output);

        if (strcmp(safe_output, expected_revised) == 0) {
                printf("success!\n");
                success = 1;
        } else {
                printf("failure! Output did not match expected.\n");
                fprintf(stderr, "Test FAILED: Output mismatch.\n");
                fprintf(stderr, "  Expected: %s\n", expected_revised);
                fprintf(stderr, "  Actual:   %s\n", safe_output);
        }

        free(safe_output);
        return success;
}
