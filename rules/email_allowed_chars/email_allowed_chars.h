#ifndef EMAIL_ALLOWED_CHARS_H
#define EMAIL_ALLOWED_CHARS_H

#include "../../misc/sanitizec_rule.h"

sanitizec_rule_result_t email_allowed_chars_apply(sanitizec_span_t input,
                                                  sanitizec_buffer_t* output,
                                                  sanitizec_span_t* result,
                                                  char** errmsg);

#endif
