#ifndef URL_COMPONENT_ENCODE_H
#define URL_COMPONENT_ENCODE_H

#include "../../misc/sanitizec_rule.h"

sanitizec_rule_result_t url_component_encode_apply(sanitizec_span_t input,
                                                   sanitizec_buffer_t* output,
                                                   sanitizec_span_t* result,
                                                   char** errmsg);

#endif
