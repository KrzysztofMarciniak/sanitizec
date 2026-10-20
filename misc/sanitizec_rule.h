#ifndef SANITIZEC_RULE_H
#define SANITIZEC_RULE_H

#include <stddef.h>

#include "sanitizec_buffer.h"

typedef struct {
        const char* data;
        size_t length;
} sanitizec_span_t;

typedef enum {
        SANITIZEC_RULE_FAILED,
        SANITIZEC_RULE_UNCHANGED,
        SANITIZEC_RULE_VIEW,   /* Borrowed slice of the input span. */
        SANITIZEC_RULE_CHANGED /* Result points to the output buffer. */
} sanitizec_rule_result_t;

#endif
