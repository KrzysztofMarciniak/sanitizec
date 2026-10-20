#ifndef ASCII_PRINTABLE_ONLY_H
#define ASCII_PRINTABLE_ONLY_H

#include "../../misc/sanitizec_buffer.h"

int ascii_printable_only_apply(const char* input, sanitizec_buffer_t* output,
                               char** errmsg);

#endif
