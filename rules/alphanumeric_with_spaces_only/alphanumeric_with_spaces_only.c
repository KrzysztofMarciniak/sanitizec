#include "alphanumeric_with_spaces_only.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "../../misc/strdup_safe.h"

char* alphanumeric_with_spaces_apply(char* input, char** errmsg) {
        if (errmsg) *errmsg = NULL;
        if (!input) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Alphanumeric with Spaces Rule: Input is NULL.");
                return NULL;
        }

        size_t len   = strlen(input);
        char* output = (char*)malloc(len + 1);
        if (!output) {
                free(input);
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Alphanumeric with Spaces Rule: Allocation "
                            "failed.");
                return NULL;
        }

        size_t j = 0;
        for (size_t i = 0; i < len; i++) {
                if (isalnum((unsigned char)input[i]) || input[i] == ' ') {
                        output[j++] = input[i];
                }
        }

        output[j] = '\0';
        free(input);
        return output;
}
