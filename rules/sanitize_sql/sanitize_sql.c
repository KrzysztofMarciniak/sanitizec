#include "sanitize_sql.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "../../misc/strdup_safe.h"

// Structure to hold a SQL keyword and its length
typedef struct {
        const char* keyword;
        size_t length;
} sql_keyword_t;

// List of SQL keywords to be removed (case-insensitive).
// Includes common DML commands and known attack patterns (e.g., 1=1 for
// tautology, SLEEP for timing attacks).
static const sql_keyword_t keywords[] =
    {
        {"SELECT", 6}, {"INSERT", 6}, {"UPDATE", 6},
        {"DELETE", 6}, {"UNION", 5},  {"DROP", 4},
        {"CONCAT", 6}, {"PRAGMA", 6},// Specifically requested keyword
        {"1=1", 3},                  // Tautology
        {"SLEEP", 5}                 // Timing attack function
};

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

                // 1. Check if the remaining input is long enough for the
                // current keyword
                if (current_pos + kw->length <= input_len) {
                        int match = 1;

                        // 2. Perform case-insensitive comparison
                        for (size_t i = 0; i < kw->length; i++) {
                                if (tolower((
                                        unsigned char)input[current_pos + i]) !=
                                    tolower((unsigned char)kw->keyword[i])) {
                                        match = 0;
                                        break;
                                }
                        }

                        // 3. If a match is found, return its length
                        if (match) {
                                return kw->length;
                        }
                }
        }
        return 0;// No keyword matched at this position
}

/**
 * @brief Applies the SQL Safe sanitization rule.
 *
 * @param input The string to sanitize (will be freed by this function).
 * @param errmsg Pointer to a char* to hold an error message on failure.
 * @return The sanitized string, or NULL on failure.
 */
char* sql_safe_apply(char* input, char** errmsg) {
        if (errmsg) *errmsg = NULL;
        if (!input) {
                if (errmsg)
                        *errmsg = strdup_safe("SQL-Safe Rule: Input is NULL.");
                return NULL;
        }

        size_t len = strlen(input);
        // Allocate an output buffer. It can be no larger than the input.
        char* output = (char*)malloc(len + 1);
        if (!output) {
                free(input);
                if (errmsg)
                        *errmsg =
                            strdup_safe("SQL-Safe Rule: Allocation failed.");
                return NULL;
        }

        size_t j = 0;// index for output
        for (size_t i = 0; i < len;) {
                // Check if a keyword starts at the current position 'i'
                size_t skip_length = check_for_keyword(input, len, i);

                if (skip_length > 0) {
                        // A keyword was matched (e.g., "SELECT"). Skip it
                        // entirely.
                        i += skip_length;
                } else {
                        // No keyword matched. Copy the character and advance
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
