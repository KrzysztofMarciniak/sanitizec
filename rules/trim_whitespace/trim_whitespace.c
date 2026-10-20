#include "trim_whitespace.h"

#include <ctype.h>
#include <stdint.h>
#include <string.h>

#include "../../misc/strdup_safe.h"

int trim_whitespace_apply(const char* input, sanitizec_buffer_t* output,
                          char** errmsg) {
        if (errmsg) *errmsg = NULL;

        if (!input || !output) {
                if (errmsg)
                        *errmsg =
                            strdup_safe("Trim Whitespace Rule: Input is NULL.");
                return 0;
        }

        size_t len   = strlen(input);
        size_t start = 0;
        while (start < len && isspace((unsigned char)input[start])) {
                start++;
        }

        if (start == len) {
                if (!sanitizec_buffer_reserve(output, 1)) {
                        if (errmsg)
                                *errmsg = strdup_safe(
                                    "Trim Whitespace Rule: Memory allocation "
                                    "failed.");
                        return 0;
                }
                if (!sanitizec_buffer_set_length(output, 0)) {
                        if (errmsg)
                                *errmsg = strdup_safe(
                                    "Trim Whitespace Rule: Memory allocation "
                                    "failed.");
                        return 0;
                }
                return 1;
        }

        size_t end = len;
        while (end > start && isspace((unsigned char)input[end - 1])) {
                end--;
        }

        size_t trimmed_len = end - start;
        if (trimmed_len == SIZE_MAX ||
            !sanitizec_buffer_reserve(output, trimmed_len + 1)) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Trim Whitespace Rule: Memory allocation failed.");
                return 0;
        }

        memcpy(output->data, input + start, trimmed_len);
        if (!sanitizec_buffer_set_length(output, trimmed_len)) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Trim Whitespace Rule: Memory allocation failed.");
                return 0;
        }
        return 1;
}
