#include "sanitize_lfi.h"

#include <stdint.h>
#include <string.h>

#include "../../misc/strdup_safe.h"

int lfi_apply(const char* input, sanitizec_buffer_t* output, char** errmsg) {
        if (errmsg) *errmsg = NULL;
        if (!input || !output) {
                if (errmsg) *errmsg = strdup_safe("LFI Rule: Input is NULL.");
                return 0;
        }

        size_t len = strlen(input);
        if (len == SIZE_MAX || !sanitizec_buffer_reserve(output, len + 1)) {
                if (errmsg)
                        *errmsg = strdup_safe("LFI Rule: Allocation failed.");
                return 0;
        }

        size_t j = 0;
        for (size_t i = 0; i < len;) {
                if (i + 3 <= len && input[i] == '.' && input[i + 1] == '.' &&
                    input[i + 2] == '/') {
                        i += 3;
                        continue;
                }

                if (i + 2 <= len && input[i] == '.' && input[i + 1] == '.') {
                        if (i + 2 == len || input[i + 2] != '/') {
                                i += 2;
                                continue;
                        }
                }

                output->data[j++] = input[i++];
        }

        if (!sanitizec_buffer_set_length(output, j)) {
                if (errmsg)
                        *errmsg = strdup_safe("LFI Rule: Allocation failed.");
                return 0;
        }
        return 1;
}
