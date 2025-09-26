#include "sanitize_lfi.h"

#include <stdlib.h>
#include <string.h>

#include "../../misc/strdup_safe.h"

/**
 * @brief Applies the LFI sanitization rule, removing directory traversal
 * sequences like "../" and "..".
 * * @param input The string to sanitize (will be freed by this function).
 * @param errmsg Pointer to a char* to hold an error message on failure.
 * @return The sanitized string, or NULL on failure.
 */
char* lfi_apply(char* input, char** errmsg) {
        if (errmsg) *errmsg = NULL;
        if (!input) {
                if (errmsg) *errmsg = strdup_safe("LFI Rule: Input is NULL.");
                return NULL;
        }

        size_t len   = strlen(input);
        char* output = (char*)malloc(len + 1);
        if (!output) {
                free(input);
                if (errmsg)
                        *errmsg = strdup_safe("LFI Rule: Allocation failed.");
                return NULL;
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

                output[j++] = input[i++];
        }

        output[j] = '\0';

        free(input);

        return output;
}
