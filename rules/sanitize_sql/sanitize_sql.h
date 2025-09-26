#ifndef SANITIZE_SQL_H_
#define SANITIZE_SQL_H_

/**
 * @brief Applies the SQL Safe sanitization rule.
 *
 * This rule removes common SQL keywords (SELECT, INSERT, DELETE, PRAGMA, etc.)
 * from the input string in a case-insensitive manner.
 * The calling function is responsible for freeing the original 'input' string.
 *
 * @param input The string to sanitize (ownership is transferred to this
 * function).
 * @param errmsg Pointer to a char* to hold an error message on failure.
 * @return The sanitized string (must be freed by the caller), or NULL on
 * failure.
 */
char* sql_safe_apply(char* input, char** errmsg);

#endif// SANITIZE_SQL_H_
