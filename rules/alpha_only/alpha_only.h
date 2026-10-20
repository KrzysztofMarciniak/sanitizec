#ifndef SANITIZEC_RULE_ALPHA_ONLY_H
#define SANITIZEC_RULE_ALPHA_ONLY_H

#include "../../misc/sanitizec_buffer.h"

/**
 * @brief Removes all non-alphabetical characters from the string.
 * Only keeps A-Z, a-z.
 *
 * @param input Input string.
 * @param output Buffer for the sanitized result.
 * @param errmsg Optional dynamically allocated error message on failure.
 * @return Nonzero on success.
 */
int alpha_only_apply(const char* input, sanitizec_buffer_t* output,
                     char** errmsg);

#endif// SANITIZEC_RULE_ALPHA_ONLY_H
