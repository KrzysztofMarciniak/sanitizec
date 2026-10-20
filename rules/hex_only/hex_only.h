#ifndef HEX_ONLY_H_
#define HEX_ONLY_H_

#include "../../misc/sanitizec_rule.h"

sanitizec_rule_result_t hex_only_apply(sanitizec_span_t input,
                                       sanitizec_buffer_t* output,
                                       sanitizec_span_t* result, char** errmsg);

#endif// HEX_ONLY_H_
