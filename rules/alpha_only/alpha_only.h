#ifndef SANITIZEC_RULE_ALPHA_ONLY_H
#define SANITIZEC_RULE_ALPHA_ONLY_H

/**
 * @brief Removes all non-alphabetical characters from the string.
 * Only keeps A-Z, a-z.
 *
 * @param input A dynamically allocated input string. Ownership is transferred.
 * @param errmsg Optional error message pointer (set to dynamically allocated message on failure).
 * @return char* A new dynamically allocated sanitized string, or NULL on failure.
 */
char* alpha_only_apply(char* input, char** errmsg);

#endif// SANITIZEC_RULE_ALPHA_ONLY_H
