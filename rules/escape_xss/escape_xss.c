#include "escape_xss.h"

#include <stdint.h>
#include <string.h>

#include "../../misc/strdup_safe.h"

/**
 * @brief Applies XSS escaping (HTML encoding) to specific characters.
 * @param input The dynamically allocated string to be escaped (ownership
 * transferred and freed here).
 * @param errmsg A pointer to a char* which will be set to a dynamically
 * allocated error message on failure, or NULL on success.
 * @return char* A new, escaped, dynamically allocated string.
 */
int escape_xss_apply(const char* input, sanitizec_buffer_t* output,
                     char** errmsg) {
        if (errmsg) *errmsg = NULL;

        if (!input || !output) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "XSS Escape Rule: Input string is NULL.");
                return 0;
        }

        size_t len     = strlen(input);
        size_t new_len = 0;
        for (size_t i = 0; i < len; i++) {
                size_t growth;
                switch (input[i]) {
                        case '&':// becomes &amp; (5 chars, +4)
                        case '\'':
                                growth = 5;
                                break;
                        case '"':// becomes &quot; (6 chars, +5)
                                growth = 6;
                                break;
                        case '<':// becomes &lt; (4 chars, +3)
                        case '>':// becomes &gt; (4 chars, +3)
                                growth = 4;
                                break;
                        default:
                                growth = 1;
                                break;
                }
                if (new_len > SIZE_MAX - growth - 1) {
                        if (errmsg)
                                *errmsg = strdup_safe(
                                    "XSS Escape Rule: Output is too large.");
                        return 0;
                }
                new_len += growth;
        }

        if (!sanitizec_buffer_reserve(output, new_len + 1)) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "XSS Escape Rule: Memory allocation failed for "
                            "output string.");
                return 0;
        }

        size_t j = 0;
        for (size_t i = 0; i < len; i++) {
                switch (input[i]) {
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
                                output->data[j++] = input[i];
                                break;
                }
        }

        if (!sanitizec_buffer_set_length(output, new_len)) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "XSS Escape Rule: Memory allocation failed for "
                            "output string.");
                return 0;
        }
        return 1;
}
