#ifndef SANITIZEC_RULE_NUMERIC_ONLY_H
#define SANITIZEC_RULE_NUMERIC_ONLY_H

#include "../../misc/sanitizec_rule.h"

/**
 * @brief Removes all non-numeric characters from the string.
 * Keeps only 0-9.
 */
sanitizec_rule_result_t numeric_only_apply(sanitizec_span_t input,
                                           sanitizec_buffer_t* output,
                                           sanitizec_span_t* result,
                                           char** errmsg);

#endif// SANITIZEC_RULE_NUMERIC_ONLY_H
