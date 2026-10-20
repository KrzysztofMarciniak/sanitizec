#ifndef HEX_ONLY_H_
#define HEX_ONLY_H_

#include "../../misc/sanitizec_buffer.h"

int hex_only_apply(const char* input, sanitizec_buffer_t* output,
                   char** errmsg);

#endif// HEX_ONLY_H_
