#ifndef ALPHANUMERIC_WITH_SPACES_ONLY_H_
#define ALPHANUMERIC_WITH_SPACES_ONLY_H_

#include "../../misc/sanitizec_rule.h"

sanitizec_rule_result_t alphanumeric_with_spaces_apply(
    sanitizec_span_t input, sanitizec_buffer_t* output,
    sanitizec_span_t* result, char** errmsg);

#endif// ALPHANUMERIC_WITH_SPACES_ONLY_H_
