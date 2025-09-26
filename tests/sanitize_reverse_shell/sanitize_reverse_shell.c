#include "sanitize_reverse_shell.h"

#include <sanitizec.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Runs a comprehensive test case for reverse shell sanitization.
 *
 * This test function validates the sanitizec library's ability to:
 * - Remove potentially dangerous shell commands
 * - Strip out IP addresses and network-related patterns
 * - Clean metacharacters and suspicious syntax
 *
 * @return int 1 if the test passes successfully, 0 if it fails
 */
int run_reverse_shell_safe_test(void) {
        const char* input_revised =
            "nc -l -p 4444 &"
            "BASH -i > /DEV/TCP/127.0.0.1/4444 0>&1"
            "BUSYBOX sh -c 'mkfifo /tmp/pipe'"
            "socket = new Socket(host, port)"
            "UserID=1 & password=1"
            "TEST: sh *sh"
            "10.1.1.255:80"
            "200.200.200.200-END"
            "This is not an IP 123.4. but 1.1.1.1 is.";

        const char* expected_revised =
            " -l -p 4444 "
            " -i > 4444 0>1"
            "  -c ' pipe'"
            " = new (host, port)"
            "UserID=1  password=1"
            "TEST:  *"
            ":80"
            "-END"
            "This is not an IP 123.4. but  is.";

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
