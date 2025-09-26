#include "escape_xss.h"

#include <stdlib.h>
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
char* escape_xss_apply(char* input, char** errmsg) {
        // Clear any previous error state
        if (errmsg) *errmsg = NULL;

        if (!input) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "XSS Escape Rule: Input string is NULL.");
                return NULL;
        }

        size_t len     = strlen(input);
        size_t new_len = 0;
        size_t i, j = 0;

        // --- 1. Calculate new required length ---
        for (i = 0; i < len; i++) {
                switch (input[i]) {
                        case '&':// becomes &amp; (5 chars, +4)
                                new_len += 5;
                                break;
                        case '<':// becomes &lt; (4 chars, +3)
                        case '>':// becomes &gt; (4 chars, +3)
                                new_len += 4;
                                break;
                        case '"':// becomes &quot; (6 chars, +5)
                                new_len += 6;
                                break;
                        case '\'':// becomes &#39; (5 chars, +4)
                                new_len += 5;
                                break;
                        default:
                                new_len += 1;
                                break;
                }
        }

        // Optimization: if no escaping is needed, return original input
        if (new_len == len) {
                return input;// No change, return original string
        }

        // --- 2. Allocate new buffer ---
        char* new_string = (char*)malloc(new_len + 1);// +1 for null terminator
        if (!new_string) {
                free(input);// Free the original string since we failed to
                            // allocate the new one
                if (errmsg)
                        *errmsg = strdup_safe(
                            "XSS Escape Rule: Memory allocation failed for "
                            "output string.");
                return NULL;
        }

        // --- 3. Copy and Escape ---
        for (i = 0; i < len; i++) {
                switch (input[i]) {
                        case '&':
                                memcpy(&new_string[j], "&amp;", 5);
                                j += 5;
                                break;
                        case '<':
                                memcpy(&new_string[j], "&lt;", 4);
                                j += 4;
                                break;
                        case '>':
                                memcpy(&new_string[j], "&gt;", 4);
                                j += 4;
                                break;
                        case '"':
                                memcpy(&new_string[j], "&quot;", 6);
                                j += 6;
                                break;
                        case '\'':
                                memcpy(&new_string[j], "&#39;", 5);
                                j += 5;
                                break;
                        default:
                                new_string[j++] = input[i];
                                break;
                }
        }

        new_string[new_len] = '\0';// Null-terminate the new string

        // --- 4. Cleanup and Return ---
        free(input);// Free the original input string
        return new_string;
}
