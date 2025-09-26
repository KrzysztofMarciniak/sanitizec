#ifndef SANITIZEC_H
#define SANITIZEC_H

// --- Rule Definitions ---
// Define rule bitmasks for the sole XSS rule
#define SANITIZEC_RULE_NONE         0
#define SANITIZEC_RULE_XSS_ESCAPE   (1 << 0) // Handles '<', '>', '&', '"', "'"
#define SANITIZEC_RULE_WHITESPACE_TRIM (1 <<1 )

// --- Function Prototypes ---

/**
 * @brief Applies XSS escaping to an input string synchronously.
 * This is a stateless operation.
 *
 * @param input The original string to sanitize (will not be modified).
 * @param ruleset A bitmask of SANITIZEC_RULE_X flags indicating which rules to apply.
 * @param errmsg A pointer to a char* which will be set to a dynamically allocated
 * error message on failure, or NULL on success. Caller must free if set.
 * @return char* A new, dynamically allocated sanitized string, or NULL on error or if input is NULL.
 * The caller is responsible for freeing the returned string.
 */
char* sanitizec_apply(const char* input, int ruleset, char **errmsg);

#endif // SANITIZEC_H
