#ifndef SANITIZE_REVERSE_SHELL_H_
#define SANITIZE_REVERSE_SHELL_H_

#include "../../misc/sanitizec_rule.h"

sanitizec_rule_result_t reverse_shell_safe_apply(sanitizec_span_t input,
                                                 sanitizec_buffer_t* output,
                                                 sanitizec_span_t* result,
                                                 char** errmsg);

#endif// SANITIZE_REVERSE_SHELL_H_
