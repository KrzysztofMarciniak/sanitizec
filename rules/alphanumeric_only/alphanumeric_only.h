#ifndef SANITIZEC_RULE_ALPHANUMERIC_ONLY_H
#define SANITIZEC_RULE_ALPHANUMERIC_ONLY_H

#include "../../misc/sanitizec_buffer.h"

/**
 * @brief Removes all characters that are not letters or digits.
 * Keeps only A-Z, a-z, and 0-9.
 */
int alphanumeric_only_apply(const char* input, sanitizec_buffer_t* output,
                            char** errmsg);

#endif// SANITIZEC_RULE_ALPHANUMERIC_ONLY_H
