#include "ascii_printable_only.h"

#include <stdlib.h>
#include <string.h>

#include "../../misc/strdup_safe.h"

char* ascii_printable_only_apply(char* input, char** errmsg) {
        if (errmsg) *errmsg = NULL;
        if (!input) {
                if (errmsg)
                        *errmsg =
                            strdup_safe("Printable ASCII rule: Input is NULL.");
                return NULL;
        }

        size_t len   = strlen(input);
        char* output = (char*)malloc(len + 1);
        if (!output) {
                free(input);
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Printable ASCII rule: Allocation "
                            "failed.");
                return NULL;
        }

        size_t j = 0;
        for (size_t i = 0; i < len; i++) {
                unsigned char c = (unsigned char)input[i];
                if (c >= 0x20 && c <= 0x7E) {
                        output[j++] = (char)c;
                }
        }

        output[j] = '\0';
        free(input);
        return output;
}
