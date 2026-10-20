#ifndef ALPHANUMERIC_WITH_SPACES_ONLY_H_
#define ALPHANUMERIC_WITH_SPACES_ONLY_H_

#include "../../misc/sanitizec_buffer.h"

int alphanumeric_with_spaces_apply(const char* input,
                                   sanitizec_buffer_t* output,
                                   char** errmsg);

#endif// ALPHANUMERIC_WITH_SPACES_ONLY_H_
