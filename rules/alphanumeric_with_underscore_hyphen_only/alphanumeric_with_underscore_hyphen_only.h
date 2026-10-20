#ifndef ALPHANUMERIC_WITH_UNDERSCORE_HYPHEN_ONLY_H
#define ALPHANUMERIC_WITH_UNDERSCORE_HYPHEN_ONLY_H

#include "../../misc/sanitizec_buffer.h"

int alphanumeric_with_underscore_hyphen_only_apply(
    const char* input, sanitizec_buffer_t* output, char** errmsg);

#endif
