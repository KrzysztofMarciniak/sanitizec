#ifndef SANITIZEC_RULE_ESCAPE_XSS_H
#define SANITIZEC_RULE_ESCAPE_XSS_H

#include <stddef.h>// For size_t

/**
 * @brief Applies XSS escaping (HTML encoding) to specific characters.
 * Replaces: '&', '<', '>', '"', and "'".
 *
 * @param input The string to be escaped. This string must be dynamically
 * allocated (ownership transferred and freed by this function).
 * @param errmsg A pointer to a char* which will be set to a dynamically
 * allocated error message on failure, or NULL on success.
 * @return char* A new, escaped, dynamically allocated string, or NULL on
 * allocation failure.
 */
char* escape_xss_apply(char* input, char** errmsg);

#endif// SANITIZEC_RULE_ESCAPE_XSS_H
