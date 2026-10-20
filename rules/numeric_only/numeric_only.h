#ifndef SANITIZEC_RULE_NUMERIC_ONLY_H
#define SANITIZEC_RULE_NUMERIC_ONLY_H

#include "../../misc/sanitizec_buffer.h"

/**
 * @brief Removes all non-numeric characters from the string.
 * Keeps only 0-9.
 */
int numeric_only_apply(const char* input, sanitizec_buffer_t* output,
                       char** errmsg);

#endif// SANITIZEC_RULE_NUMERIC_ONLY_H
