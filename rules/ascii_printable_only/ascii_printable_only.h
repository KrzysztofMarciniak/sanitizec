#ifndef ASCII_PRINTABLE_ONLY_H
#define ASCII_PRINTABLE_ONLY_H

#include "../../misc/sanitizec_rule.h"

sanitizec_rule_result_t ascii_printable_only_apply(sanitizec_span_t input,
                                                   sanitizec_buffer_t* output,
                                                   sanitizec_span_t* result,
                                                   char** errmsg);

#endif
