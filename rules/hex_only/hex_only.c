#include "hex_only.h"

#include <ctype.h>
#include <stdint.h>
#include <string.h>

#include "../../misc/strdup_safe.h"

static int is_hex_char(char c) {
        return ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                (c >= 'A' && c <= 'F'));
}

int hex_only_apply(const char* input, sanitizec_buffer_t* output,
                   char** errmsg) {
        if (errmsg) *errmsg = NULL;
        if (!input || !output) {
                if (errmsg)
                        *errmsg = strdup_safe("Hex-only Rule: Input is NULL.");
                return 0;
        }

        size_t len = strlen(input);
        if (len == SIZE_MAX || !sanitizec_buffer_reserve(output, len + 1)) {
                if (errmsg)
                        *errmsg =
                            strdup_safe("Hex-only Rule: Allocation failed.");
                return 0;
        }

        size_t j = 0;
        for (size_t i = 0; i < len; ++i) {
                if (is_hex_char(input[i])) {
                        output->data[j++] = input[i];
                }
        }

        if (!sanitizec_buffer_set_length(output, j)) {
                if (errmsg)
                        *errmsg =
                            strdup_safe("Hex-only Rule: Allocation failed.");
                return 0;
        }
        return 1;
}
