#include "url_component_encode.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sanitizec.h"

static int is_expected_unreserved(unsigned char c) {
        return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' ||
                c == '~');
}

int run_url_component_encode_test(void) {
        const char* input =
            "https://example.com/a b?x=1&y=\xE2\x98\x83 %2F-_.~";
        const char* expected =
            "https%3A%2F%2Fexample.com%2Fa%20b%3Fx%3D1%26y%3D%E2%98%83%20"
            "%252F-_.~";
        char* errmsg      = NULL;
        char* safe_output = sanitizec_apply(
            input, SANITIZEC_RULE_URL_COMPONENT_ENCODE, &errmsg);
        int success = 0;

        printf("testing: [URL component encoding]\n");
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

        for (unsigned int byte = 1; success && byte <= UCHAR_MAX; byte++) {
                char single_byte[2] = {(char)byte, '\0'};
                char byte_expected[4];
                unsigned char c = (unsigned char)byte;
                if (is_expected_unreserved(c)) {
                        byte_expected[0] = (char)c;
                        byte_expected[1] = '\0';
                } else {
                        static const char hex[] = "0123456789ABCDEF";
                        byte_expected[0]        = '%';
                        byte_expected[1]        = hex[c >> 4];
                        byte_expected[2]        = hex[c & 0x0F];
                        byte_expected[3]        = '\0';
                }

                char* byte_output = sanitizec_apply(
                    single_byte, SANITIZEC_RULE_URL_COMPONENT_ENCODE, &errmsg);
                if (!byte_output || strcmp(byte_output, byte_expected) != 0) {
                        fprintf(stderr,
                                "Test FAILED: URL encoding byte 0x%02X.\n",
                                byte);
                        success = 0;
                }
                free(byte_output);
                free(errmsg);
                errmsg = NULL;
        }

        free(errmsg);
        free(safe_output);
        return success;
}
