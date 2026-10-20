#ifndef SANITIZEC_RULE_TRIM_WHITESPACE_H
#define SANITIZEC_RULE_TRIM_WHITESPACE_H

#include "../../misc/sanitizec_rule.h"

/**
 * @brief Trims leading and trailing whitespace from a string.
 *
 * @param input Input span to trim.
 * @param output Buffer for the trimmed string.
 * @param result Receives the unchanged input or trimmed view.
 * @param errmsg Optional dynamically allocated error message on failure.
 * @return Rule outcome: failed, unchanged, or a trimmed view.
 */
sanitizec_rule_result_t trim_whitespace_apply(sanitizec_span_t input,
                                              sanitizec_buffer_t* output,
                                              sanitizec_span_t* result,
                                              char** errmsg);

#endif// SANITIZEC_RULE_TRIM_WHITESPACE_H
