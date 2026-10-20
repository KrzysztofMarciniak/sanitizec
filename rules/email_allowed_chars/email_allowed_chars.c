#include "email_allowed_chars.h"

#include <stdlib.h>
#include <string.h>

#include "../../misc/strdup_safe.h"

static int is_allowed(unsigned char c) {
        return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '%' ||
                c == '+' || c == '-' || c == '@');
}

char* email_allowed_chars_apply(char* input, char** errmsg) {
        if (errmsg) *errmsg = NULL;
        if (!input) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Email character allowlist rule: Input is NULL.");
                return NULL;
        }

        size_t len   = strlen(input);
        char* output = (char*)malloc(len + 1);
        if (!output) {
                free(input);
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Email character allowlist rule: "
                            "Allocation failed.");
                return NULL;
        }

        size_t j = 0;
        for (size_t i = 0; i < len; i++) {
                unsigned char c = (unsigned char)input[i];
                if (is_allowed(c)) {
                        output[j++] = (char)c;
                }
        }

        output[j] = '\0';
        free(input);
        return output;
}
