#ifndef SANITIZEC_H
#define SANITIZEC_H

#define SANITIZEC_RULE_NONE 0
#define SANITIZEC_RULE_XSS_ESCAPE (1 << 0)
#define SANITIZEC_RULE_WHITESPACE_TRIM (1 << 1)
#define SANITIZEC_RULE_ALPHA_ONLY (1 << 2)
#define SANITIZEC_RULE_NUMERIC_ONLY (1 << 3)
#define SANITIZEC_RULE_ALPHANUMERIC_ONLY (1 << 4)
#define SANITIZEC_RULE_LFI (1 << 5)
#define SANITIZEC_RULE_SQL (1 << 6)
#define SANITIZEC_RULE_REVERSE_SHELL (1 << 7)
#define SANITIZEC_RULE_ALPHANUMERIC_WITH_SPACES_ONLY (1 << 8)

/**
 * @brief Applies sanitization rules to an input string.
 *
 * @param input The original string to sanitize.
 * @param ruleset Bitmask of sanitization rules to apply.
 * @param errmsg Pointer to store error message if sanitization fails.
 * @return char* Sanitized string, or NULL on error.
 */
char* sanitizec_apply(const char* input, int ruleset, char** errmsg);

#endif
