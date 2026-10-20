#ifndef SANITIZEC_RULE_ESCAPE_XSS_H
#define SANITIZEC_RULE_ESCAPE_XSS_H

#include "../../misc/sanitizec_rule.h"

/**
 * @brief Applies XSS escaping (HTML encoding) to specific characters.
 * Replaces: '&', '<', '>', '"', and "'".
 *
 * @param input Input span to escape.
 * @param output Buffer for the escaped string.
 * @param result Receives the unchanged input or escaped output span.
 * @param errmsg Optional dynamically allocated error message on failure.
 * @return Rule outcome: failed, unchanged, or buffered output.
 */
sanitizec_rule_result_t escape_xss_apply(sanitizec_span_t input,
                                         sanitizec_buffer_t* output,
                                         sanitizec_span_t* result,
                                         char** errmsg);

#endif// SANITIZEC_RULE_ESCAPE_XSS_H
