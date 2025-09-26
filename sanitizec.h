#ifndef SANITIZEC_H // Updated header guard
#define SANITIZEC_H

#include <stddef.h>

// Built-in Rules
#define SANITIZEC_RULE_HTML_ESCAPE 0x01 // Updated macro prefix
#define SANITIZEC_RULE_SQL_ESCAPE 0x02
#define SANITIZEC_RULE_URL_ENCODE 0x04
// Reserve 0x08, 0x10, etc., for future individual rules

// Built-in Rulesets (combinations of rules)
#define SANITIZEC_RULESET_WEB_SAFE (SANITIZEC_RULE_HTML_ESCAPE | SANITIZEC_RULE_URL_ENCODE) // Updated macro prefix
#define SANITIZEC_RULESET_DB_SAFE (SANITIZEC_RULE_SQL_ESCAPE)

/**
 * @brief Applies the specified ruleset to an input string.
 * * @param input The null-terminated string to be sanitized.
 * @param ruleset A bitmask of rules to apply (e.g., SANITIZEC_RULESET_WEB_SAFE).
 * @return A newly allocated, null-terminated string containing the sanitized content,
 * or NULL on failure. The caller is responsible for freeing the returned string.
 */
char* sanitizec_apply(const char* input, int ruleset); // Updated function name

#endif // SANITIZEC_H
