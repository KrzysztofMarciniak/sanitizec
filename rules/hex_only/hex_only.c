#include "hex_only.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "../../misc/strdup_safe.h"

static int is_hex_char(char c) {
        return ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                (c >= 'A' && c <= 'F'));
}

char* hex_only_apply(char* input, char** errmsg) {
        if (errmsg) *errmsg = NULL;
        if (!input) {
                if (errmsg)
                        *errmsg = strdup_safe("Hex-only Rule: Input is NULL.");
                return NULL;
        }

        size_t len   = strlen(input);
        char* output = (char*)malloc(len + 1);
        if (!output) {
                free(input);
                if (errmsg)
                        *errmsg =
                            strdup_safe("Hex-only Rule: Allocation failed.");
                return NULL;
        }

        size_t j = 0;
        for (size_t i = 0; i < len; ++i) {
                if (is_hex_char(input[i])) {
                        output[j++] = input[i];
                }
        }

        output[j] = '\0';
        free(input);
        return output;
}
