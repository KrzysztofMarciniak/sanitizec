#ifndef SANITIZE_SQL_H_
#define SANITIZE_SQL_H_

#include "../../misc/sanitizec_rule.h"

/**
 * @brief Applies the SQL Safe sanitization rule.
 *
 * This rule removes common SQL keywords (SELECT, INSERT, DELETE, PRAGMA, etc.)
 * from the input string in a case-insensitive manner.
 *
 * @param input Input span to sanitize.
 * @param output Buffer for the sanitized string.
 * @param result Receives the unchanged input or sanitized output span.
 * @param errmsg Optional error message on failure.
 * @return Rule outcome: failed, unchanged, or buffered output.
 */
sanitizec_rule_result_t sql_safe_apply(sanitizec_span_t input,
                                       sanitizec_buffer_t* output,
                                       sanitizec_span_t* result, char** errmsg);

#endif// SANITIZE_SQL_H_
