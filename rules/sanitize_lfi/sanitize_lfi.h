#ifndef SANITIZE_LFI_H_
#define SANITIZE_LFI_H_

#include "../../misc/sanitizec_rule.h"

/**
 * @brief Applies the LFI (Local File Inclusion) sanitization rule.
 *
 * This rule removes directory traversal sequences ("../" and "..") from the
 * input string.
 *
 * @param input Input span to sanitize.
 * @param output Buffer for the sanitized string.
 * @param result Receives the unchanged input or sanitized output span.
 * @param errmsg Optional error message on failure.
 * @return Rule outcome: failed, unchanged, or buffered output.
 */
sanitizec_rule_result_t lfi_apply(sanitizec_span_t input,
                                  sanitizec_buffer_t* output,
                                  sanitizec_span_t* result, char** errmsg);

#endif// SANITIZE_LFI_H_
