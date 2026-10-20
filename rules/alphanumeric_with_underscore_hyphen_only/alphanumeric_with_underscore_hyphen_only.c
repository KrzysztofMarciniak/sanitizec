#include "alphanumeric_with_underscore_hyphen_only.h"

#include <stdint.h>
#include <string.h>

#include "../../misc/strdup_safe.h"

static int is_allowed(unsigned char c) {
        return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') || c == '_' || c == '-');
}

int alphanumeric_with_underscore_hyphen_only_apply(
    const char* input, sanitizec_buffer_t* output, char** errmsg) {
        if (errmsg) *errmsg = NULL;
        if (!input || !output) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Alphanumeric underscore-hyphen rule: Input is "
                            "NULL.");
                return 0;
        }

        size_t len = strlen(input);
        if (len == SIZE_MAX || !sanitizec_buffer_reserve(output, len + 1)) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Alphanumeric underscore-hyphen rule: Allocation "
                            "failed.");
                return 0;
        }

        size_t j = 0;
        for (size_t i = 0; i < len; i++) {
                unsigned char c = (unsigned char)input[i];
                if (is_allowed(c)) {
                        output->data[j++] = (char)c;
                }
        }

        if (!sanitizec_buffer_set_length(output, j)) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Alphanumeric underscore-hyphen rule: Allocation "
                            "failed.");
                return 0;
        }
        return 1;
}
