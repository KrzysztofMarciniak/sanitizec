#include "alphanumeric_with_underscore_hyphen_only.h"

#include <stdlib.h>
#include <string.h>

#include "../../misc/strdup_safe.h"

static int is_allowed(unsigned char c) {
        return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') || c == '_' || c == '-');
}

char* alphanumeric_with_underscore_hyphen_only_apply(char* input,
                                                     char** errmsg) {
        if (errmsg) *errmsg = NULL;
        if (!input) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Alphanumeric underscore-hyphen rule: Input is "
                            "NULL.");
                return NULL;
        }

        size_t len   = strlen(input);
        char* output = (char*)malloc(len + 1);
        if (!output) {
                free(input);
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Alphanumeric underscore-hyphen rule: Allocation "
                            "failed.");
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
