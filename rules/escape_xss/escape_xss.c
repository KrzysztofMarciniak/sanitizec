#include "escape_xss.h"

#include <stdint.h>
#include <string.h>

#include "../../misc/strdup_safe.h"

static const unsigned char output_extra[256] = {
    ['&'] = 4, ['\''] = 4, ['"'] = 5, ['<'] = 3, ['>'] = 3,
};

/**
 * @brief Applies XSS escaping (HTML encoding) to specific characters.
 * @param input Input span to escape.
 * @param output Scratch buffer for the escaped span.
 * @param result Receives the unchanged input or escaped output span.
 * @param errmsg Optional allocated error message on failure.
 */
sanitizec_rule_result_t escape_xss_apply(sanitizec_span_t input,
                                         sanitizec_buffer_t* output,
                                         sanitizec_span_t* result,
                                         char** errmsg) {
        if (errmsg) *errmsg = NULL;

        if (!input.data || !output || !result) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "XSS Escape Rule: Input string is NULL.");
                return SANITIZEC_RULE_FAILED;
        }

        size_t len     = input.length;
        size_t new_len = 0;
        for (size_t i = 0; i < len; i++) {
                size_t growth = 1 + output_extra[(unsigned char)input.data[i]];
                if (new_len > SIZE_MAX - growth - 1) {
                        if (errmsg)
                                *errmsg = strdup_safe(
                                    "XSS Escape Rule: Output is too large.");
                        return SANITIZEC_RULE_FAILED;
                }
                new_len += growth;
        }

        if (new_len == len) {
                *result = input;
                return SANITIZEC_RULE_UNCHANGED;
        }

        if (!sanitizec_buffer_reserve(output, new_len + 1)) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "XSS Escape Rule: Memory allocation failed for "
                            "output string.");
                return SANITIZEC_RULE_FAILED;
        }

        size_t j   = 0;
        size_t run = 0;
        for (size_t i = 0; i < len; i++) {
                unsigned char c = (unsigned char)input.data[i];
                if (!output_extra[c]) continue;

                size_t run_len = i - run;
                if (run_len)
                        memcpy(output->data + j, input.data + run, run_len);
                j += run_len;
                switch (c) {
                        case '&':
                                memcpy(&output->data[j], "&amp;", 5);
                                j += 5;
                                break;
                        case '<':
                                memcpy(&output->data[j], "&lt;", 4);
                                j += 4;
                                break;
                        case '>':
                                memcpy(&output->data[j], "&gt;", 4);
                                j += 4;
                                break;
                        case '"':
                                memcpy(&output->data[j], "&quot;", 6);
                                j += 6;
                                break;
                        case '\'':
                                memcpy(&output->data[j], "&#39;", 5);
                                j += 5;
                                break;
                        default:
                                output->data[j++] = (char)c;
                                break;
                }
                run = i + 1;
        }
        size_t run_len = len - run;
        if (run_len) memcpy(output->data + j, input.data + run, run_len);
        j += run_len;

        if (!sanitizec_buffer_set_length(output, new_len)) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "XSS Escape Rule: Memory allocation failed for "
                            "output string.");
                return SANITIZEC_RULE_FAILED;
        }
        *result = (sanitizec_span_t){output->data, j};
        return SANITIZEC_RULE_CHANGED;
}
