#ifndef URL_COMPONENT_ENCODE_H
#define URL_COMPONENT_ENCODE_H

#include "../../misc/sanitizec_buffer.h"

int url_component_encode_apply(const char* input, sanitizec_buffer_t* output,
                               char** errmsg);

#endif
