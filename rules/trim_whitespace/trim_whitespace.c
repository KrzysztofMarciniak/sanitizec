#include "trim_whitespace.h"

#include <ctype.h>
#include <stdint.h>
#include <string.h>

#include "../../misc/strdup_safe.h"

sanitizec_rule_result_t trim_whitespace_apply(sanitizec_span_t input,
                                              sanitizec_buffer_t* output,
                                              sanitizec_span_t* result,
                                              char** errmsg) {
        if (errmsg) *errmsg = NULL;

        if (!input.data || !output || !result) {
                if (errmsg)
                        *errmsg =
                            strdup_safe("Trim Whitespace Rule: Input is NULL.");
                return SANITIZEC_RULE_FAILED;
        }

        size_t len   = input.length;
        size_t start = 0;
        while (start < len && isspace((unsigned char)input.data[start])) {
                start++;
        }
        size_t end = len;
        while (end > start && isspace((unsigned char)input.data[end - 1])) {
                end--;
        }

        if (start == 0 && end == len) {
                *result = input;
                return SANITIZEC_RULE_UNCHANGED;
        }

        *result = (sanitizec_span_t){input.data + start, end - start};
        return SANITIZEC_RULE_VIEW;
}
