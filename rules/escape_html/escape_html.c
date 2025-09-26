#include "escape_html.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Placeholder function to demonstrate a rule implementation.
 * * In a full version, this would perform HTML character escaping.
 * For now, it just prints a message and returns a copy.
 */
char* escape_html_apply(const char* input) {
    if (!input) return NULL;

    // Placeholder implementation: create a new string with " [HTML-ESCAPED]" appended
    size_t len = strlen(input);
    const char* suffix = " [HTML-ESCAPED]";
    size_t suffix_len = strlen(suffix);

    char* output = malloc(len + suffix_len + 1);
    if (output) {
        strcpy(output, input);
        strcat(output, suffix);
        printf("--- HTML rule applied: String length increased by %zu ---\n", suffix_len);
    }
    return output;
}
