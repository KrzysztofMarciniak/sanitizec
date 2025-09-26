#ifndef SANITIZEC_RULE_TRIM_WHITESPACE_H
#define SANITIZEC_RULE_TRIM_WHITESPACE_H

/**
 * @brief Trims leading and trailing whitespace from a dynamically allocated string.
 *
 * @param input The input string (must be dynamically allocated).
 * Ownership is transferred and freed inside.
 *
 * @param errmsg A pointer to a char* which will be set to a dynamically allocated
 * error message on failure, or NULL on success.
 *
 * @return char* A new, trimmed, dynamically allocated string. NULL on error.
 */
char* trim_whitespace_apply(char* input, char **errmsg);

#endif // SANITIZEC_RULE_TRIM_WHITESPACE_H
