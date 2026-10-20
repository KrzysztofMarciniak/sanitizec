#include "sanitize_lfi.h"

#include <stdint.h>
#include <string.h>

#include "../../misc/strdup_safe.h"

sanitizec_rule_result_t lfi_apply(sanitizec_span_t input,
                                  sanitizec_buffer_t* output,
                                  sanitizec_span_t* result, char** errmsg) {
        if (errmsg) *errmsg = NULL;
        if (!input.data || !output || !result) {
                if (errmsg) *errmsg = strdup_safe("LFI Rule: Input is NULL.");
                return SANITIZEC_RULE_FAILED;
        }

        size_t len         = input.length;
        size_t first_match = 0;
        while (first_match + 1 < len && !(input.data[first_match] == '.' &&
                                          input.data[first_match + 1] == '.')) {
                first_match++;
        }
        if (first_match + 1 >= len) {
                *result = input;
                return SANITIZEC_RULE_UNCHANGED;
        }

        if (len == SIZE_MAX || !sanitizec_buffer_reserve(output, len + 1)) {
                if (errmsg)
                        *errmsg = strdup_safe("LFI Rule: Allocation failed.");
                return SANITIZEC_RULE_FAILED;
        }

        size_t j = 0;
        for (size_t i = 0; i < len;) {
                if (i + 3 <= len && input.data[i] == '.' &&
                    input.data[i + 1] == '.' && input.data[i + 2] == '/') {
                        i += 3;
                        continue;
                }

                if (i + 2 <= len && input.data[i] == '.' &&
                    input.data[i + 1] == '.') {
                        if (i + 2 == len || input.data[i + 2] != '/') {
                                i += 2;
                                continue;
                        }
                }

                output->data[j++] = input.data[i++];
        }

        if (!sanitizec_buffer_set_length(output, j)) {
                if (errmsg)
                        *errmsg = strdup_safe("LFI Rule: Allocation failed.");
                return SANITIZEC_RULE_FAILED;
        }
        *result = (sanitizec_span_t){output->data, j};
        return SANITIZEC_RULE_CHANGED;
}
