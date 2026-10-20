#include "url_component_encode.h"

#include <stdint.h>
#include <string.h>

#include "../../misc/strdup_safe.h"

static const unsigned char unreserved[256] = {
    ['0'] = 1, ['1'] = 1, ['2'] = 1, ['3'] = 1, ['4'] = 1, ['5'] = 1, ['6'] = 1,
    ['7'] = 1, ['8'] = 1, ['9'] = 1, ['A'] = 1, ['B'] = 1, ['C'] = 1, ['D'] = 1,
    ['E'] = 1, ['F'] = 1, ['G'] = 1, ['H'] = 1, ['I'] = 1, ['J'] = 1, ['K'] = 1,
    ['L'] = 1, ['M'] = 1, ['N'] = 1, ['O'] = 1, ['P'] = 1, ['Q'] = 1, ['R'] = 1,
    ['S'] = 1, ['T'] = 1, ['U'] = 1, ['V'] = 1, ['W'] = 1, ['X'] = 1, ['Y'] = 1,
    ['Z'] = 1, ['a'] = 1, ['b'] = 1, ['c'] = 1, ['d'] = 1, ['e'] = 1, ['f'] = 1,
    ['g'] = 1, ['h'] = 1, ['i'] = 1, ['j'] = 1, ['k'] = 1, ['l'] = 1, ['m'] = 1,
    ['n'] = 1, ['o'] = 1, ['p'] = 1, ['q'] = 1, ['r'] = 1, ['s'] = 1, ['t'] = 1,
    ['u'] = 1, ['v'] = 1, ['w'] = 1, ['x'] = 1, ['y'] = 1, ['z'] = 1, ['-'] = 1,
    ['.'] = 1, ['_'] = 1, ['~'] = 1,
};

static int is_unreserved(unsigned char c) { return unreserved[c]; }

int url_component_encode_apply(const char* input, sanitizec_buffer_t* output,
                               char** errmsg) {
        static const char hex[] = "0123456789ABCDEF";

        if (errmsg) *errmsg = NULL;
        if (!input || !output) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "URL component encoding rule: Input is NULL.");
                return 0;
        }

        size_t len     = strlen(input);
        size_t new_len = 0;
        for (size_t i = 0; i < len; i++) {
                size_t growth = is_unreserved((unsigned char)input[i]) ? 1 : 3;
                if (new_len > SIZE_MAX - growth - 1) {
                        if (errmsg)
                                *errmsg = strdup_safe(
                                    "URL component encoding rule: Output is "
                                    "too large.");
                        return 0;
                }
                new_len += growth;
        }

        if (!sanitizec_buffer_reserve(output, new_len + 1)) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "URL component encoding rule: Allocation failed.");
                return 0;
        }

        size_t j = 0;
        for (size_t i = 0; i < len; i++) {
                unsigned char c = (unsigned char)input[i];
                if (is_unreserved(c)) {
                        output->data[j++] = (char)c;
                } else {
                        output->data[j++] = '%';
                        output->data[j++] = hex[c >> 4];
                        output->data[j++] = hex[c & 0x0F];
                }
        }

        if (!sanitizec_buffer_set_length(output, j)) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "URL component encoding rule: Allocation failed.");
                return 0;
        }
        return 1;
}
