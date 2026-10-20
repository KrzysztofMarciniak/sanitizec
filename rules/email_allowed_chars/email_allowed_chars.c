#include "email_allowed_chars.h"

#include <stdint.h>
#include <string.h>

#include "../../misc/strdup_safe.h"

static int is_allowed(unsigned char c) {
        return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '%' ||
                c == '+' || c == '-' || c == '@');
}

sanitizec_rule_result_t email_allowed_chars_apply(sanitizec_span_t input,
                                                  sanitizec_buffer_t* output,
                                                  sanitizec_span_t* result,
                                                  char** errmsg) {
        if (errmsg) *errmsg = NULL;
        if (!input.data || !output || !result) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Email character allowlist rule: Input is NULL.");
                return SANITIZEC_RULE_FAILED;
        }

        size_t len  = input.length;
        int changed = 0;
        for (size_t i = 0; i < len; i++) {
                if (!is_allowed((unsigned char)input.data[i])) changed = 1;
        }
        if (!changed) {
                *result = input;
                return SANITIZEC_RULE_UNCHANGED;
        }

        if (len == SIZE_MAX || !sanitizec_buffer_reserve(output, len + 1)) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Email character allowlist rule: "
                            "Allocation failed.");
                return SANITIZEC_RULE_FAILED;
        }

        size_t j = 0;
        for (size_t i = 0; i < len; i++) {
                unsigned char c = (unsigned char)input.data[i];
                if (is_allowed(c)) {
                        output->data[j++] = (char)c;
                }
        }

        if (!sanitizec_buffer_set_length(output, j)) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Email character allowlist rule: "
                            "Allocation failed.");
                return SANITIZEC_RULE_FAILED;
        }
        *result = (sanitizec_span_t){output->data, j};
        return SANITIZEC_RULE_CHANGED;
}
