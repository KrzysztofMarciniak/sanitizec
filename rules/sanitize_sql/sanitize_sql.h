#ifndef SANITIZE_SQL_H_
#define SANITIZE_SQL_H_

#include "../../misc/sanitizec_buffer.h"

/**
 * @brief Applies the SQL Safe sanitization rule.
 *
 * This rule removes common SQL keywords (SELECT, INSERT, DELETE, PRAGMA, etc.)
 * from the input string in a case-insensitive manner.
 *
 * @param input The string to sanitize.
 * @param output Buffer for the sanitized string.
 * @param errmsg Optional error message on failure.
 * @return Nonzero on success.
 */
int sql_safe_apply(const char* input, sanitizec_buffer_t* output,
                   char** errmsg);

#endif// SANITIZE_SQL_H_
