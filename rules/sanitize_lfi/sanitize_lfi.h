#ifndef SANITIZE_LFI_H_
#define SANITIZE_LFI_H_

/**
 * @brief Applies the LFI (Local File Inclusion) sanitization rule.
 *
 * This rule removes directory traversal sequences ("../" and "..") from the
 * input string. The calling function is responsible for freeing the original
 * 'input' string.
 *
 * @param input The string to sanitize (ownership is transferred to this
 * function).
 * @param errmsg Pointer to a char* to hold an error message on failure.
 * @return The sanitized string (must be freed by the caller), or NULL on
 * failure.
 */
char* lfi_apply(char* input, char** errmsg);

#endif// SANITIZE_LFI_H_
