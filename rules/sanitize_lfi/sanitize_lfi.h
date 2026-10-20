#ifndef SANITIZE_LFI_H_
#define SANITIZE_LFI_H_

#include "../../misc/sanitizec_buffer.h"

/**
 * @brief Applies the LFI (Local File Inclusion) sanitization rule.
 *
 * This rule removes directory traversal sequences ("../" and "..") from the
 * input string.
 *
 * @param input The string to sanitize.
 * @param output Buffer for the sanitized string.
 * @param errmsg Optional error message on failure.
 * @return Nonzero on success.
 */
int lfi_apply(const char* input, sanitizec_buffer_t* output, char** errmsg);

#endif// SANITIZE_LFI_H_
