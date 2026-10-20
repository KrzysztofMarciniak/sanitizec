#ifndef SANITIZEC_RULE_ALPHANUMERIC_ONLY_H
#define SANITIZEC_RULE_ALPHANUMERIC_ONLY_H

#include "../../misc/sanitizec_rule.h"

/**
 * @brief Removes all characters that are not letters or digits.
 * Keeps only A-Z, a-z, and 0-9.
 */
sanitizec_rule_result_t alphanumeric_only_apply(sanitizec_span_t input,
                                                sanitizec_buffer_t* output,
                                                sanitizec_span_t* result,
                                                char** errmsg);

#endif// SANITIZEC_RULE_ALPHANUMERIC_ONLY_H
