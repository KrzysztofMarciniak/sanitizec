#ifndef SANITIZEC_RULE_NUMERIC_ONLY_H
#define SANITIZEC_RULE_NUMERIC_ONLY_H

/**
 * @brief Removes all non-numeric characters from the string.
 * Keeps only 0-9.
 */
char* numeric_only_apply(char* input, char** errmsg);

#endif// SANITIZEC_RULE_NUMERIC_ONLY_H
