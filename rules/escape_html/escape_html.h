#ifndef ESCAPE_HTML_H
#define ESCAPE_HTML_H

#include <stddef.h>

/**
 * @brief Escapes HTML special characters in an input string.
 * * @param input The string to be escaped.
 * @return A newly allocated string with HTML characters escaped, or NULL on error.
 * The caller must free the returned string.
 */
char* escape_html_apply(const char* input);

#endif // ESCAPE_HTML_H
