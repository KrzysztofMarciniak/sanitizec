#include "sanitizec.h"

#include <ctype.h>
#include <locale.h>
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

typedef sanitizec_rule_result_t (*rule_func_t)(sanitizec_span_t,
                                               sanitizec_buffer_t*,
                                               sanitizec_span_t*, char**);

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

/* Keep in sync with rules_map so unknown bits do not block final selection. */
static const int ruleset_mask =
    SANITIZEC_RULE_XSS_ESCAPE | SANITIZEC_RULE_WHITESPACE_TRIM |
    SANITIZEC_RULE_ALPHA_ONLY | SANITIZEC_RULE_NUMERIC_ONLY |
    SANITIZEC_RULE_ALPHANUMERIC_ONLY | SANITIZEC_RULE_LFI | SANITIZEC_RULE_SQL |
    SANITIZEC_RULE_REVERSE_SHELL |
    SANITIZEC_RULE_ALPHANUMERIC_WITH_SPACES_ONLY | SANITIZEC_RULE_HEX_ONLY |
    SANITIZEC_RULE_URL_COMPONENT_ENCODE | SANITIZEC_RULE_ASCII_PRINTABLE_ONLY |
    SANITIZEC_RULE_ALPHANUMERIC_WITH_UNDERSCORE_HYPHEN_ONLY |
    SANITIZEC_RULE_EMAIL_ALLOWED_CHARS;

#ifdef SANITIZEC_ENABLE_CACHE
static const int cacheable_ruleset_mask =
    SANITIZEC_RULE_XSS_ESCAPE | SANITIZEC_RULE_LFI | SANITIZEC_RULE_SQL |
    SANITIZEC_RULE_REVERSE_SHELL | SANITIZEC_RULE_URL_COMPONENT_ENCODE;
#endif

static int is_character_filter(int flag) {
        switch (flag) {
                case SANITIZEC_RULE_ALPHA_ONLY:
                case SANITIZEC_RULE_NUMERIC_ONLY:
                case SANITIZEC_RULE_ALPHANUMERIC_ONLY:
                case SANITIZEC_RULE_ALPHANUMERIC_WITH_SPACES_ONLY:
                case SANITIZEC_RULE_HEX_ONLY:
                case SANITIZEC_RULE_ASCII_PRINTABLE_ONLY:
                case SANITIZEC_RULE_ALPHANUMERIC_WITH_UNDERSCORE_HYPHEN_ONLY:
                case SANITIZEC_RULE_EMAIL_ALLOWED_CHARS:
                        return 1;
                default:
                        return 0;
        }
}

#ifdef SANITIZEC_ENABLE_CACHE
static int should_cache_ruleset(int ruleset) {
        return (ruleset & cacheable_ruleset_mask) != 0;
}
#endif

static int is_ascii_alphanumeric(unsigned char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9');
}

static _Thread_local int cached_filter_flags = -1;
static _Thread_local char cached_filter_locale[128];
static _Thread_local unsigned char cached_filter_table[256];

static unsigned char* character_filter_table(int flags) {
        const int locale_flags = SANITIZEC_RULE_ALPHA_ONLY |
                                 SANITIZEC_RULE_NUMERIC_ONLY |
                                 SANITIZEC_RULE_ALPHANUMERIC_ONLY |
                                 SANITIZEC_RULE_ALPHANUMERIC_WITH_SPACES_ONLY;
        const char* locale =
            flags & locale_flags ? setlocale(LC_CTYPE, NULL) : "";
        if (!locale) locale = "";
        size_t locale_len = strlen(locale);

        if (cached_filter_flags == flags &&
            locale_len < sizeof(cached_filter_locale) &&
            strcmp(cached_filter_locale, locale) == 0)
                return cached_filter_table;

        for (unsigned int value = 0; value < 256; value++) {
                unsigned char c = (unsigned char)value;
                int allowed     = 1;
                if (flags & SANITIZEC_RULE_ALPHA_ONLY)
                        allowed &= isalpha(c) != 0;
                if (flags & SANITIZEC_RULE_NUMERIC_ONLY)
                        allowed &= isdigit(c) != 0;
                if (flags & SANITIZEC_RULE_ALPHANUMERIC_ONLY)
                        allowed &= isalnum(c) != 0;
                if (flags & SANITIZEC_RULE_ALPHANUMERIC_WITH_SPACES_ONLY)
                        allowed &= isalnum(c) != 0 || c == ' ';
                if (flags & SANITIZEC_RULE_HEX_ONLY)
                        allowed &= (c >= '0' && c <= '9') ||
                                   (c >= 'a' && c <= 'f') ||
                                   (c >= 'A' && c <= 'F');
                if (flags & SANITIZEC_RULE_ASCII_PRINTABLE_ONLY)
                        allowed &= c >= 0x20 && c <= 0x7e;
                if (flags &
                    SANITIZEC_RULE_ALPHANUMERIC_WITH_UNDERSCORE_HYPHEN_ONLY)
                        allowed &=
                            is_ascii_alphanumeric(c) || c == '_' || c == '-';
                if (flags & SANITIZEC_RULE_EMAIL_ALLOWED_CHARS)
                        allowed &= is_ascii_alphanumeric(c) || c == '.' ||
                                   c == '_' || c == '%' || c == '+' ||
                                   c == '-' || c == '@';
                cached_filter_table[value] = (unsigned char)allowed;
        }

        cached_filter_flags =
            locale_len < sizeof(cached_filter_locale) ? flags : -1;
        if (cached_filter_flags >= 0) {
                memcpy(cached_filter_locale, locale, locale_len + 1);
        }
        return cached_filter_table;
}

static sanitizec_rule_result_t apply_character_filters(
    sanitizec_span_t input, int flags, sanitizec_buffer_t* output,
    sanitizec_span_t* result) {
        unsigned char* keep = character_filter_table(flags);

        size_t len  = input.length;
        int changed = 0;
        for (size_t i = 0; i < len; i++) {
                if (!keep[(unsigned char)input.data[i]]) changed = 1;
        }
        if (!changed) {
                *result = input;
                return SANITIZEC_RULE_UNCHANGED;
        }
        if (len == SIZE_MAX || !sanitizec_buffer_reserve(output, len + 1))
                return SANITIZEC_RULE_FAILED;

        char* dst = output->data;
        size_t j  = 0;
        for (size_t i = 0; i < len; i++) {
                unsigned char c = (unsigned char)input.data[i];
                dst[j]          = (char)c;
                j += keep[c];
        }
        if (!sanitizec_buffer_set_length(output, j))
                return SANITIZEC_RULE_FAILED;
        *result = (sanitizec_span_t){dst, j};
        return SANITIZEC_RULE_CHANGED;
}

char* sanitizec_apply(const char* input, int ruleset, char** errmsg) {
        if (errmsg) *errmsg = NULL;

        if (!input) {
                if (errmsg) *errmsg = strdup_safe("Input string is NULL.");
                return NULL;
        }

        size_t input_len = strlen(input);
#ifdef SANITIZEC_ENABLE_CACHE
        if (input_len <= SANITIZEC_CACHE_MAX_INPUT_BYTES &&
            should_cache_ruleset(ruleset)) {
                char* cached_string =
                    sanitizec_cache_get(input, input_len, ruleset);
                if (cached_string) return cached_string;
        }
#endif

        sanitizec_buffer_t buffers[2];
        sanitizec_buffer_init(&buffers[0]);
        sanitizec_buffer_init(&buffers[1]);
        sanitizec_buffer_t* current_buffer = NULL;
        sanitizec_buffer_t* output_buffer  = &buffers[0];
        sanitizec_span_t current_span      = {input, input_len};
        int remaining_ruleset              = ruleset & ruleset_mask;

        for (int i = 0; rules_map[i].flag != 0; i++) {
                if (!(ruleset & rules_map[i].flag)) continue;

                sanitizec_rule_result_t status;
                sanitizec_span_t next_span;
                const char* rule_name;
                if (is_character_filter(rules_map[i].flag)) {
                        int filter_flags = 0;
                        int j            = i;
                        while (rules_map[j].flag != 0) {
                                if ((ruleset & rules_map[j].flag) &&
                                    !is_character_filter(rules_map[j].flag))
                                        break;
                                if (ruleset & rules_map[j].flag) {
                                        filter_flags |= rules_map[j].flag;
                                        remaining_ruleset &= ~rules_map[j].flag;
                                }
                                j++;
                        }
                        i         = j - 1;
                        rule_name = "Character filters";
                        sanitizec_buffer_reset(output_buffer);
                        if (remaining_ruleset == 0)
                                sanitizec_buffer_force_heap(output_buffer);
                        status =
                            apply_character_filters(current_span, filter_flags,
                                                    output_buffer, &next_span);
                } else {
                        remaining_ruleset &= ~rules_map[i].flag;
                        rule_name = rules_map[i].name;
                        sanitizec_buffer_reset(output_buffer);
                        if (remaining_ruleset == 0)
                                sanitizec_buffer_force_heap(output_buffer);
                        status = rules_map[i].func(current_span, output_buffer,
                                                   &next_span, errmsg);
                }

                if (status == SANITIZEC_RULE_FAILED) {
                        if (errmsg && *errmsg == NULL) {
                                size_t msg_len =
                                    strlen(rule_name) +
                                    strlen(" failed during execution.") + 1;
                                char* default_msg = malloc(msg_len);
                                if (default_msg) {
                                        snprintf(default_msg, msg_len,
                                                 "%s failed during execution.",
                                                 rule_name);
                                        *errmsg = default_msg;
                                }
                        }
                        sanitizec_buffer_destroy(&buffers[0]);
                        sanitizec_buffer_destroy(&buffers[1]);
                        return NULL;
                }
                current_span = next_span;
                if (status == SANITIZEC_RULE_CHANGED) {
                        current_buffer = output_buffer;
                        output_buffer  = output_buffer == &buffers[0]
                                             ? &buffers[1]
                                             : &buffers[0];
                }
        }

        char* result;
        if (current_buffer && current_span.data == current_buffer->data &&
            current_span.length == current_buffer->length) {
                result = sanitizec_buffer_take_string(current_buffer);
        } else {
                result = malloc(current_span.length + 1);
                if (result) {
                        if (current_span.length) {
                                memcpy(result, current_span.data,
                                       current_span.length);
                        }
                        result[current_span.length] = '\0';
                }
        }

        sanitizec_buffer_destroy(&buffers[0]);
        sanitizec_buffer_destroy(&buffers[1]);
        if (!result) {
                if (errmsg)
                        *errmsg =
                            strdup_safe("Failed to allocate output string.");
                return NULL;
        }

#ifdef SANITIZEC_ENABLE_CACHE
        if (input_len <= SANITIZEC_CACHE_MAX_INPUT_BYTES &&
            should_cache_ruleset(ruleset)) {
                sanitizec_cache_store(input, input_len, ruleset, result,
                                      current_span.length);
        }
#endif
        return result;
}
