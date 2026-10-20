#include "ascii_printable_only.h"

#include <stdint.h>
#include <string.h>

#include "../../misc/strdup_safe.h"

int ascii_printable_only_apply(const char* input, sanitizec_buffer_t* output,
                               char** errmsg) {
        if (errmsg) *errmsg = NULL;
        if (!input || !output) {
                if (errmsg)
                        *errmsg =
                            strdup_safe("Printable ASCII rule: Input is NULL.");
                return 0;
        }

        size_t len = strlen(input);
        if (len == SIZE_MAX || !sanitizec_buffer_reserve(output, len + 1)) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Printable ASCII rule: Allocation "
                            "failed.");
                return 0;
        }

        size_t j = 0;
        for (size_t i = 0; i < len; i++) {
                unsigned char c = (unsigned char)input[i];
                if (c >= 0x20 && c <= 0x7E) {
                        output->data[j++] = (char)c;
                }
        }

        if (!sanitizec_buffer_set_length(output, j)) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Printable ASCII rule: Allocation failed.");
                return 0;
        }
        return 1;
}
