#include "sanitize_sql.h"

#include <stdint.h>
#include <string.h>

#include "../../misc/sanitizec_pattern.h"
#include "../../misc/strdup_safe.h"

sanitizec_rule_result_t sql_safe_apply(sanitizec_span_t input,
                                       sanitizec_buffer_t* output,
                                       sanitizec_span_t* result,
                                       char** errmsg) {
        if (errmsg) *errmsg = NULL;
        if (!input.data || !output || !result) {
                if (errmsg)
                        *errmsg = strdup_safe("SQL-Safe Rule: Input is NULL.");
                return SANITIZEC_RULE_FAILED;
        }

        size_t len = input.length;
        if (!sanitizec_pattern_scan(input.data, len, &sanitizec_sql_automaton,
                                    NULL)) {
                *result = input;
                return SANITIZEC_RULE_UNCHANGED;
        }

        if (len == SIZE_MAX || !sanitizec_buffer_reserve(output, len + 1)) {
                if (errmsg)
                        *errmsg =
                            strdup_safe("SQL-Safe Rule: Allocation failed.");
                return SANITIZEC_RULE_FAILED;
        }

        memset(output->data, 0, len);
        sanitizec_pattern_scan(input.data, len, &sanitizec_sql_automaton,
                               (unsigned char*)output->data);
        size_t j = 0;
        for (size_t i = 0; i < len;) {
                size_t skip_length = (unsigned char)output->data[i];
                if (skip_length > 0) {
                        i += skip_length;
                } else {
                        output->data[j++] = input.data[i++];
                }
        }

        if (!sanitizec_buffer_set_length(output, j)) {
                if (errmsg)
                        *errmsg =
                            strdup_safe("SQL-Safe Rule: Allocation failed.");
                return SANITIZEC_RULE_FAILED;
        }
        *result = (sanitizec_span_t){output->data, j};
        return SANITIZEC_RULE_CHANGED;
}
