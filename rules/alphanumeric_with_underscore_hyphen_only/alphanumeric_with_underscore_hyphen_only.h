#ifndef ALPHANUMERIC_WITH_UNDERSCORE_HYPHEN_ONLY_H
#define ALPHANUMERIC_WITH_UNDERSCORE_HYPHEN_ONLY_H

#include "../../misc/sanitizec_rule.h"

sanitizec_rule_result_t alphanumeric_with_underscore_hyphen_only_apply(
    sanitizec_span_t input, sanitizec_buffer_t* output,
    sanitizec_span_t* result, char** errmsg);

#endif
