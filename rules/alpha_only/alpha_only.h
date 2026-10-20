#ifndef SANITIZEC_RULE_ALPHA_ONLY_H
#define SANITIZEC_RULE_ALPHA_ONLY_H

#include "../../misc/sanitizec_rule.h"

/**
 * @brief Removes all non-alphabetical characters from the string.
 * Only keeps A-Z, a-z.
 *
 * @param input Input span.
 * @param output Buffer for the sanitized result.
 * @param result Receives the unchanged input or sanitized output span.
 * @param errmsg Optional dynamically allocated error message on failure.
 * @return Rule outcome: failed, unchanged, or buffered output.
 */
sanitizec_rule_result_t alpha_only_apply(sanitizec_span_t input,
                                         sanitizec_buffer_t* output,
                                         sanitizec_span_t* result,
                                         char** errmsg);

#endif// SANITIZEC_RULE_ALPHA_ONLY_H
