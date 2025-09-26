#include "sanitize_reverse_shell.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "../../misc/strdup_safe.h"

// Structure to hold a reverse shell keyword/pattern and its length
typedef struct {
        const char* pattern;
        size_t length;
} shell_pattern_t;

static const shell_pattern_t patterns[] = {
    {"nc", 2},     {"netcat", 6}, {"bash", 4}, {"busybox", 7},
    {"&", 1},      {"sh", 2},     {"dev", 3},  {"tcp", 3},
    {"mkfifo", 6}, {"tmp", 3},    {"/", 1},    {"socket", 6}};

static const size_t PATTERN_COUNT = sizeof(patterns) / sizeof(patterns[0]);

/**
 * @brief Helper function to check for a case-insensitive match of any fixed
 * pattern.
 *
 * For single-character patterns ('/', '&'), the match is case-sensitive as they
 * are not letters.
 *
 * @param input The entire input string.
 * @param input_len The length of the input string.
 * @param current_pos The starting position to check for a pattern match.
 * @return The length of the matched pattern, or 0 if no pattern is matched.
 */
static size_t check_for_pattern(const char* input, size_t input_len,
                                size_t current_pos) {
        for (size_t k = 0; k < PATTERN_COUNT; k++) {
                const shell_pattern_t* pat = &patterns[k];

                // 1. Check if the remaining input is long enough for the
                // current pattern
                if (current_pos + pat->length <= input_len) {
                        int match = 1;

                        // 2. Perform comparison (case-insensitive for letters,
                        // case-sensitive otherwise)
                        for (size_t i = 0; i < pat->length; i++) {
                                char input_char   = input[current_pos + i];
                                char pattern_char = pat->pattern[i];

                                if (isalpha((unsigned char)input_char)) {
                                        if (tolower(
                                                (unsigned char)input_char) !=
                                            tolower(
                                                (unsigned char)pattern_char)) {
                                                match = 0;
                                                break;
                                        }
                                } else {
                                        // Non-alpha characters like '/', '&',
                                        // '.', '*' are compared
                                        // case-sensitively
                                        if (input_char != pattern_char) {
                                                match = 0;
                                                break;
                                        }
                                }
                        }

                        // 3. If a match is found, return its length
                        if (match) {
                                return pat->length;
                        }
                }
        }
        return 0;// No pattern matched at this position
}

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

        // Loop until we run out of input or break the IP pattern
        while (i < input_len) {
                if (isdigit((unsigned char)input[i])) {
                        octet_digit_count++;
                        if (octet_digit_count >
                            3) {         // Max 3 digits per octet (e.g., 255)
                                return 0;// Too many digits for a valid octet,
                                         // stop matching IP here
                        }
                        i++;
                } else if (input[i] == '.') {
                        // Must have had at least one digit before the dot
                        if (octet_digit_count == 0) {
                                return 0;// Dot without preceding digit
                        }

                        dot_count++;
                        if (dot_count > 3) {// Max 3 dots for 4 octets
                                break;// Stop here, but check if we successfully
                                      // ended a pattern
                        }

                        // Reset digit counter for the next octet
                        octet_digit_count = 0;
                        i++;
                } else {
                        // Found a non-digit, non-dot character.
                        break;
                }
        }

        // Final validation: Must have exactly 3 dots (4 octets) and the last
        // octet must have at least one digit. The loop breaks either on the
        // fourth dot or on a non-dot/non-digit character. We check for the
        // final state after the loop.
        if (dot_count == 3 && octet_digit_count > 0) {
                // If the loop broke on a non-digit/non-dot char, 'i' is the
                // character after the IP. If the loop broke because of
                // `dot_count > 3` (which is now `break`), 'i' is the character
                // after the 3rd dot. We ensure we return the length from
                // start_pos up to the point of match (i).
                return i - start_pos;
        }

        return 0;// Not a complete IP address structure
}

/**
 * @brief Applies the Reverse Shell Protection sanitization rule.
 *
 * @param input The string to sanitize (will be freed by this function).
 * @param errmsg Pointer to a char* to hold an error message on failure.
 * @return The sanitized string, or NULL on failure.
 */
char* reverse_shell_safe_apply(char* input, char** errmsg) {
        if (errmsg) *errmsg = NULL;
        if (!input) {
                if (errmsg)
                        *errmsg =
                            strdup_safe("Reverse Shell Rule: Input is NULL.");
                return NULL;
        }

        size_t len = strlen(input);
        // Allocate an output buffer. It can be no larger than the input.
        char* output = (char*)malloc(len + 1);
        if (!output) {
                free(input);
                if (errmsg)
                        *errmsg = strdup_safe(
                            "Reverse Shell Rule: Allocation failed.");
                return NULL;
        }

        size_t j = 0;// index for output
        for (size_t i = 0; i < len;) {
                size_t skip_length = 0;

                // 1. Check for fixed shell patterns
                skip_length = check_for_pattern(input, len, i);

                if (skip_length == 0) {
                        // 2. If no fixed pattern, check for variable IP pattern
                        skip_length = check_for_ip_pattern(input, len, i);
                }

                if (skip_length > 0) {
                        // A pattern (keyword or IP) was matched. Skip it
                        // entirely.
                        i += skip_length;
                } else {
                        // No pattern matched. Copy the character and advance
                        // both indices.
                        output[j++] = input[i++];
                }
        }

        output[j] = '\0';

        // Free the original string as per the library's ownership transfer
        // model
        free(input);

        return output;
}
