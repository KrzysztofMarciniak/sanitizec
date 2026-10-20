#include "sanitize_sql.h"

#include <ctype.h>
#include <stdint.h>
#include <string.h>

#include "../../misc/strdup_safe.h"

typedef struct {
        const char* keyword;
        size_t length;
} sql_keyword_t;

static const sql_keyword_t keywords[] = {
    {"SELECT", 6}, {"INSERT", 6}, {"UPDATE", 6}, {"DELETE", 6}, {"UNION", 5},
    {"DROP", 4},   {"CONCAT", 6}, {"PRAGMA", 6}, {"1=1", 3},    {"SLEEP", 5}};

static const size_t KEYWORD_COUNT = sizeof(keywords) / sizeof(keywords[0]);

/**
 * @brief Helper function to check for a case-insensitive match of any keyword.
 *
 * @param input The entire input string.
 * @param input_len The length of the input string.
 * @param current_pos The starting position to check for a keyword match.
 * @return The length of the matched keyword, or 0 if no keyword is matched.
 */
static size_t check_for_keyword(const char* input, size_t input_len,
                                size_t current_pos) {
        for (size_t k = 0; k < KEYWORD_COUNT; k++) {
                const sql_keyword_t* kw = &keywords[k];
                if (current_pos + kw->length <= input_len) {
                        int match = 1;
                        for (size_t i = 0; i < kw->length; i++) {
                                if (tolower((
                                        unsigned char)input[current_pos + i]) !=
                                    tolower((unsigned char)kw->keyword[i])) {
                                        match = 0;
                                        break;
                                }
                        }
                        if (match) {
                                return kw->length;
                        }
                }
        }
        return 0;
}

int sql_safe_apply(const char* input, sanitizec_buffer_t* output,
                   char** errmsg) {
        if (errmsg) *errmsg = NULL;
        if (!input || !output) {
                if (errmsg)
                        *errmsg = strdup_safe("SQL-Safe Rule: Input is NULL.");
                return 0;
        }

        size_t len = strlen(input);
        if (len == SIZE_MAX || !sanitizec_buffer_reserve(output, len + 1)) {
                if (errmsg)
                        *errmsg =
                            strdup_safe("SQL-Safe Rule: Allocation failed.");
                return 0;
        }

        size_t j = 0;
        for (size_t i = 0; i < len;) {
                size_t skip_length = check_for_keyword(input, len, i);

                if (skip_length > 0) {
                        i += skip_length;
                } else {
                        output->data[j++] = input[i++];
                }
        }

        if (!sanitizec_buffer_set_length(output, j)) {
                if (errmsg)
                        *errmsg =
                            strdup_safe("SQL-Safe Rule: Allocation failed.");
                return 0;
        }
        return 1;
}
