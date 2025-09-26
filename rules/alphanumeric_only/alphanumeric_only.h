#ifndef SANITIZEC_RULE_ALPHANUMERIC_ONLY_H
#define SANITIZEC_RULE_ALPHANUMERIC_ONLY_H

/**
 * @brief Removes all characters that are not letters or digits.
 * Keeps only A-Z, a-z, and 0-9.
 */
char* alphanumeric_only_apply(char* input, char** errmsg);

#endif// SANITIZEC_RULE_ALPHANUMERIC_ONLY_H
