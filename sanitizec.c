#include "sanitizec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "misc/strdup_safe.h"
#include "rules/alpha_only/alpha_only.h"
#include "rules/alphanumeric_only/alphanumeric_only.h"
#include "rules/escape_xss/escape_xss.h"
#include "rules/numeric_only/numeric_only.h"
#include "rules/sanitize_lfi/sanitize_lfi.h"
#include "rules/sanitize_sql/sanitize_sql.h"
#include "rules/trim_whitespace/trim_whitespace.h"

// --- Rule Lookup Infrastructure ---

// 1. Function signature for all rule apply
// functions (char* rule_apply(char* input, char
// **errmsg))
typedef char* (*rule_func_t)(char*, char**);

// 2. Structure to map a rule flag (bitmask) to
// its implementation function and name
typedef struct {
        int flag;
        rule_func_t func;
        const char* name;// Rule name for error reporting
} rule_map_t;

// 3. The central lookup table mapping flags to
// functions.
static const rule_map_t rules_map[] = {
    // Rule Flag                     // Function
    // Pointer             // Rule Name
    {SANITIZEC_RULE_XSS_ESCAPE, escape_xss_apply, "XSS Escape Rule"},
    {SANITIZEC_RULE_WHITESPACE_TRIM, trim_whitespace_apply,
     "Trim Whitespace Rule"},
    {SANITIZEC_RULE_ALPHA_ONLY, alpha_only_apply, "Alphabetic letters only"},
    {SANITIZEC_RULE_NUMERIC_ONLY, numeric_only_apply, "Numbers only"},
    {SANITIZEC_RULE_ALPHANUMERIC_ONLY, alphanumeric_only_apply,
     "Letters and Numbers only"},
    {SANITIZEC_RULE_LFI, lfi_apply, "Remove ../ and .."},
    {SANITIZEC_RULE_SQL, sql_safe_apply, "Remove sql keywords."},
    {0, NULL, NULL}// Sentinel
};

/**
 * @brief Applies a ruleset of sanitization
 * techniques to an input string synchronously.
 *
 * @param input The original string to sanitize
 * (will not be modified).
 * @param ruleset A bitmask of SANITIZEC_RULE_X
 * flags indicating which rules to apply.
 * @param errmsg A pointer to a char* which will
 * be set to a dynamically allocated error message
 * on failure, or NULL on success. Caller must
 * free if set.
 * @return char* A new, dynamically allocated
 * sanitized string, or NULL on error.
 */
char* sanitizec_apply(const char* input, int ruleset, char** errmsg) {
        // 1. Initialize errmsg to NULL
        if (errmsg) *errmsg = NULL;

        if (!input) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Input string is "
                            "NULL.");
                return NULL;
        }

        // Start with a copy of the input string.
        char* current_string = strdup_safe(input);
        if (!current_string) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Failed to allocate "
                            "initial copy of "
                            "input string.");
                return NULL;
        }
        // Apply rules using the data-driven map
        for (int i = 0; rules_map[i].flag != 0; i++) {
                if (ruleset & rules_map[i].flag) {
                        // Call the function
                        // associated with the
                        // flag, passing the
                        // current string and the
                        // error pointer
                        char* new_string =
                            rules_map[i].func(current_string, errmsg);

                        if (new_string == NULL) {
                                // Failure: The
                                // rule function
                                // should have
                                // already set
                                // *errmsg on
                                // failure. We
                                // provide a
                                // fallback
                                // message if it
                                // failed to set
                                // one.
                                if (errmsg && *errmsg == NULL) {
                                        size_t msg_len =
                                            strlen(rules_map[i].name) +
                                            strlen(
                                                " failed during execution.") +
                                            1;
                                        char* default_msg = malloc(msg_len);
                                        if (default_msg) {
                                                // Use snprintf for safe string
                                                // concatenation
                                                snprintf(default_msg, msg_len,
                                                         "%s failed during "
                                                         "execution.",
                                                         rules_map[i].name);
                                                *errmsg = default_msg;
                                        }
                                }
                                // The rule
                                // function is
                                // responsible for
                                // freeing
                                // `current_string`
                                // on failure.
                                return NULL;
                        }
                        // Update the pointer for
                        // the next iteration
                        current_string = new_string;
                }
        }

        // Return the final processed string.
        return current_string;
}
