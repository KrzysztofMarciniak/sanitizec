#include "trim_whitespace.h"
#include "../../misc/strdup_safe.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

char* trim_whitespace_apply(char* input, char **errmsg) {
    if (errmsg) *errmsg = NULL;

    if (!input) {
        if (errmsg) *errmsg = strdup_safe("Trim Whitespace Rule: Input is NULL.");
        return NULL;
    }

    // Find start of non-whitespace
    char *start = input;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }

    // If string is entirely whitespace
    if (*start == '\0') {
        free(input);
        return strdup_safe(""); // Return empty string
    }

    // Find end of non-whitespace
    char *end = input + strlen(input) - 1;
    while (end > start && isspace((unsigned char)*end)) {
        end--;
    }

    size_t trimmed_len = end - start + 1;

    char *result = (char *)malloc(trimmed_len + 1);
    if (!result) {
        free(input);
        if (errmsg) *errmsg = strdup_safe("Trim Whitespace Rule: Memory allocation failed.");
        return NULL;
    }

    memcpy(result, start, trimmed_len);
    result[trimmed_len] = '\0';

    free(input);
    return result;
}
