#ifndef SANITIZEC_RULE_ESCAPE_XSS_H
#define SANITIZEC_RULE_ESCAPE_XSS_H

#include "../../misc/sanitizec_buffer.h"

/**
 * @brief Applies XSS escaping (HTML encoding) to specific characters.
 * Replaces: '&', '<', '>', '"', and "'".
 *
 * @param input The string to be escaped.
 * @param output Buffer for the escaped string.
 * @param errmsg Optional dynamically allocated error message on failure.
 * @return Nonzero on success.
 */
int escape_xss_apply(const char* input, sanitizec_buffer_t* output,
                     char** errmsg);

#endif// SANITIZEC_RULE_ESCAPE_XSS_H
