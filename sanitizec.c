#include "sanitizec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef SANITIZEC_ENABLE_CACHE
#include "misc/sanitizec_cache.h"
#endif
#include "misc/sanitizec_buffer.h"
#include "misc/strdup_safe.h"
#include "rules/alpha_only/alpha_only.h"
#include "rules/alphanumeric_only/alphanumeric_only.h"
#include "rules/alphanumeric_with_spaces_only/alphanumeric_with_spaces_only.h"
#include "rules/alphanumeric_with_underscore_hyphen_only/alphanumeric_with_underscore_hyphen_only.h"
#include "rules/ascii_printable_only/ascii_printable_only.h"
#include "rules/email_allowed_chars/email_allowed_chars.h"
#include "rules/escape_xss/escape_xss.h"
#include "rules/hex_only/hex_only.h"
#include "rules/numeric_only/numeric_only.h"
#include "rules/sanitize_lfi/sanitize_lfi.h"
#include "rules/sanitize_reverse_shell/sanitize_reverse_shell.h"
#include "rules/sanitize_sql/sanitize_sql.h"
#include "rules/trim_whitespace/trim_whitespace.h"
#include "rules/url_component_encode/url_component_encode.h"

typedef int (*rule_func_t)(const char*, sanitizec_buffer_t*, char**);

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
    {SANITIZEC_RULE_URL_COMPONENT_ENCODE, url_component_encode_apply,
     "URL component encoding"},
    {SANITIZEC_RULE_ASCII_PRINTABLE_ONLY, ascii_printable_only_apply,
     "Printable ASCII only"},
    {SANITIZEC_RULE_ALPHANUMERIC_WITH_UNDERSCORE_HYPHEN_ONLY,
     alphanumeric_with_underscore_hyphen_only_apply,
     "Alphanumeric, underscore, and hyphen only"},
    {SANITIZEC_RULE_EMAIL_ALLOWED_CHARS, email_allowed_chars_apply,
     "Email-address character allowlist"},
    {0, NULL, NULL}};

char* sanitizec_apply(const char* input, int ruleset, char** errmsg) {
        if (errmsg) *errmsg = NULL;

        if (!input) {
                if (errmsg) *errmsg = strdup_safe("Input string is NULL.");
                return NULL;
        }

#ifdef SANITIZEC_ENABLE_CACHE
        char* cached_string = sanitizec_cache_get(input, ruleset);
        if (cached_string) return cached_string;
#endif

        sanitizec_buffer_t buffers[2];
        sanitizec_buffer_init(&buffers[0]);
        sanitizec_buffer_init(&buffers[1]);
        sanitizec_buffer_t* current_buffer = NULL;
        sanitizec_buffer_t* output_buffer  = &buffers[0];
        const char* current_string         = input;

        int last_rule_index = -1;
        for (int i = 0; rules_map[i].flag != 0; i++) {
                if (ruleset & rules_map[i].flag) last_rule_index = i;
        }

        for (int i = 0; rules_map[i].flag != 0; i++) {
                if (ruleset & rules_map[i].flag) {
                        sanitizec_buffer_reset(output_buffer);
                        if (i == last_rule_index)
                                sanitizec_buffer_force_heap(output_buffer);
                        if (!rules_map[i].func(current_string, output_buffer,
                                               errmsg)) {
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
                                sanitizec_buffer_destroy(&buffers[0]);
                                sanitizec_buffer_destroy(&buffers[1]);
                                return NULL;
                        }
                        current_buffer = output_buffer;
                        current_string = output_buffer->data;
                        output_buffer =
                            output_buffer == &buffers[0] ? &buffers[1]
                                                         : &buffers[0];
                }
        }

        char* result;
        if (current_buffer) {
                result = sanitizec_buffer_take_string(current_buffer);
                if (!result && errmsg)
                        *errmsg =
                            strdup_safe("Failed to allocate output string.");
        } else {
                result = strdup_safe(input);
                if (!result && errmsg)
                        *errmsg = strdup_safe(
                            "Failed to allocate initial copy of input string.");
        }

        sanitizec_buffer_destroy(&buffers[0]);
        sanitizec_buffer_destroy(&buffers[1]);
        if (!result) return NULL;

#ifdef SANITIZEC_ENABLE_CACHE
        sanitizec_cache_store(input, ruleset, result);
#endif
        return result;
}
