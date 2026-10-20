#ifndef SANITIZE_REVERSE_SHELL_H_
#define SANITIZE_REVERSE_SHELL_H_

#include "../../misc/sanitizec_buffer.h"

int reverse_shell_safe_apply(const char* input, sanitizec_buffer_t* output,
                             char** errmsg);

#endif// SANITIZE_REVERSE_SHELL_H_
