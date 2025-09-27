#include "sanitizec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "misc/strdup_safe.h"
#include "rules/alpha_only/alpha_only.h"
#include "rules/alphanumeric_only/alphanumeric_only.h"
#include "rules/alphanumeric_with_spaces_only/alphanumeric_with_spaces_only.h"
#include "rules/escape_xss/escape_xss.h"
#include "rules/hex_only/hex_only.h"
#include "rules/numeric_only/numeric_only.h"
#include "rules/sanitize_lfi/sanitize_lfi.h"
#include "rules/sanitize_reverse_shell/sanitize_reverse_shell.h"
#include "rules/sanitize_sql/sanitize_sql.h"
#include "rules/trim_whitespace/trim_whitespace.h"

typedef char* (*rule_func_t)(char*, char**);

typedef struct {
        int flag;
        rule_func_t func;
        const char* name;
} rule_map_t;

static const rule_map_t rules_map[] = {
    {SANITIZEC_RULE_XSS_ESCAPE, escape_xss_apply, "XSS Escape Rule"},
    {SANITIZEC_RULE_WHITESPACE_TRIM, trim_whitespace_apply,
     "Trim Whitespace Rule"},
    {SANITIZEC_RULE_ALPHA_ONLY, alpha_only_apply, "Alphabetic letters only"},
    {SANITIZEC_RULE_NUMERIC_ONLY, numeric_only_apply, "Numbers only"},
    {SANITIZEC_RULE_ALPHANUMERIC_ONLY, alphanumeric_only_apply,
     "Letters and Numbers only"},
    {SANITIZEC_RULE_LFI, lfi_apply, "Remove ../ and .."},
    {SANITIZEC_RULE_SQL, sql_safe_apply, "Remove sql keywords."},
    {SANITIZEC_RULE_HEX_ONLY, hex_only_apply, "hex only, good for csrf etc."},
    {SANITIZEC_RULE_ALPHANUMERIC_WITH_SPACES_ONLY,
     alphanumeric_with_spaces_apply, "Alphanumeric but with spaces."},
    {SANITIZEC_RULE_REVERSE_SHELL, reverse_shell_safe_apply,
     "Remove reverse shell keywords."},
    {0, NULL, NULL}};

char* sanitizec_apply(const char* input, int ruleset, char** errmsg) {
        if (errmsg) *errmsg = NULL;

        if (!input) {
                if (errmsg) *errmsg = strdup_safe("Input string is NULL.");
                return NULL;
        }

        char* current_string = strdup_safe(input);
        if (!current_string) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Failed to allocate initial copy of input string.");
                return NULL;
        }

        for (int i = 0; rules_map[i].flag != 0; i++) {
                if (ruleset & rules_map[i].flag) {
                        char* new_string =
                            rules_map[i].func(current_string, errmsg);

                        if (new_string == NULL) {
                                if (errmsg && *errmsg == NULL) {
                                        size_t msg_len =
                                            strlen(rules_map[i].name) +
                                            strlen(
                                                " failed during execution.") +
                                            1;
                                        char* default_msg = malloc(msg_len);
                                        if (default_msg) {
                                                snprintf(default_msg, msg_len,
                                                         "%s failed during "
                                                         "execution.",
                                                         rules_map[i].name);
                                                *errmsg = default_msg;
                                        }
                                }
                                return NULL;
                        }
                        current_string = new_string;
                }
        }

        return current_string;
}
