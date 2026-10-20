#include "sanitize_reverse_shell.h"

#include <ctype.h>
#include <stdint.h>
#include <string.h>

#include "../../misc/sanitizec_pattern.h"
#include "../../misc/strdup_safe.h"

/**
 * @brief Helper to check for a pattern that matches a four-octet IPv4 address
 * (e.g., 127.0.0.1).
 * * This function checks for the structure D.D.D.D, where D is 1 to 3 digits.
 * It does NOT check for octet validity (e.g., 999.0.0.1 is matched).
 *
 * @param input The entire input string.
 * @param input_len The length of the input string.
 * @param current_pos The starting position to check.
 * @return The length of the matched IP string (7 to 15 chars), or 0 if no IP is
 * matched.
 */
static size_t check_for_ip_pattern(const char* input, size_t input_len,
                                   size_t current_pos) {
        size_t i              = current_pos;
        int dot_count         = 0;
        int octet_digit_count = 0;
        size_t start_pos      = current_pos;

        // Check minimum length (1.1.1.1 is 7 characters)
        if (input_len - current_pos < 7) {
                return 0;
        }

        while (i < input_len) {
                if (isdigit((unsigned char)input[i])) {
                        octet_digit_count++;
                        if (octet_digit_count >
                            3) {         // Max 3 digits per octet (e.g., 255)
                                return 0;// Too many digits for a valid octet,
                        }
                        i++;
                } else if (input[i] == '.') {
                        if (octet_digit_count == 0) {
                                return 0;// Dot without preceding digit
                        }

                        dot_count++;
                        if (dot_count > 3) {
                                break;
                        }
                        octet_digit_count = 0;
                        i++;
                } else {
                        break;
                }
        }

        if (dot_count == 3 && octet_digit_count > 0) {
                return i - start_pos;
        }

        return 0;
}

sanitizec_rule_result_t reverse_shell_safe_apply(sanitizec_span_t input,
                                                 sanitizec_buffer_t* output,
                                                 sanitizec_span_t* result,
                                                 char** errmsg) {
        if (errmsg) *errmsg = NULL;
        if (!input.data || !output || !result) {
                if (errmsg)
                        *errmsg =
                            strdup_safe("Reverse Shell Rule: Input is NULL.");
                return SANITIZEC_RULE_FAILED;
        }

        size_t len  = input.length;
        int matched = sanitizec_pattern_scan(input.data, len,
                                             &sanitizec_shell_automaton, NULL);
        for (size_t i = 0; i < len && !matched; i++) {
                matched = check_for_ip_pattern(input.data, len, i) != 0;
        }
        if (!matched) {
                *result = input;
                return SANITIZEC_RULE_UNCHANGED;
        }

        if (len == SIZE_MAX || !sanitizec_buffer_reserve(output, len + 1)) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Reverse Shell Rule: Allocation failed.");
                return SANITIZEC_RULE_FAILED;
        }

        memset(output->data, 0, len);
        sanitizec_pattern_scan(input.data, len, &sanitizec_shell_automaton,
                               (unsigned char*)output->data);
        size_t j = 0;
        for (size_t i = 0; i < len;) {
                size_t skip_length = (unsigned char)output->data[i];
                if (skip_length == 0) {
                        skip_length = check_for_ip_pattern(input.data, len, i);
                }

                if (skip_length > 0) {
                        i += skip_length;
                } else {
                        output->data[j++] = input.data[i++];
                }
        }

        if (!sanitizec_buffer_set_length(output, j)) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Reverse Shell Rule: Allocation failed.");
                return SANITIZEC_RULE_FAILED;
        }
        *result = (sanitizec_span_t){output->data, j};
        return SANITIZEC_RULE_CHANGED;
}
