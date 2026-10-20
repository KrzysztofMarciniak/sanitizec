#ifndef SANITIZEC_RULE_TRIM_WHITESPACE_H
#define SANITIZEC_RULE_TRIM_WHITESPACE_H

#include "../../misc/sanitizec_buffer.h"

/**
 * @brief Trims leading and trailing whitespace from a string.
 *
 * @param input The input string.
 * @param output Buffer for the trimmed string.
 * @param errmsg Optional dynamically allocated error message on failure.
 * @return Nonzero on success.
 */
int trim_whitespace_apply(const char* input, sanitizec_buffer_t* output,
                          char** errmsg);

#endif// SANITIZEC_RULE_TRIM_WHITESPACE_H
