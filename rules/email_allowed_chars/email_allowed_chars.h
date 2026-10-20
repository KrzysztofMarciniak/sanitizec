#ifndef EMAIL_ALLOWED_CHARS_H
#define EMAIL_ALLOWED_CHARS_H

#include "../../misc/sanitizec_buffer.h"

int email_allowed_chars_apply(const char* input, sanitizec_buffer_t* output,
                              char** errmsg);

#endif
