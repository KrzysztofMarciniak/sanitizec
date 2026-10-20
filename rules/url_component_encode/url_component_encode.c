#include "url_component_encode.h"

#include <stdint.h>
#include <string.h>

#include "../../misc/strdup_safe.h"

static const unsigned char encoded_size[256] = {
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

static size_t output_size(unsigned char c) {
        return encoded_size[c] ? encoded_size[c] : 3;
}

sanitizec_rule_result_t url_component_encode_apply(sanitizec_span_t input,
                                                   sanitizec_buffer_t* output,
                                                   sanitizec_span_t* result,
                                                   char** errmsg) {
        static const char hex[] = "0123456789ABCDEF";

        if (errmsg) *errmsg = NULL;
        if (!input.data || !output || !result) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "URL component encoding rule: Input is NULL.");
                return SANITIZEC_RULE_FAILED;
        }

        size_t len     = input.length;
        size_t new_len = 0;
        for (size_t i = 0; i < len; i++) {
                size_t growth = output_size((unsigned char)input.data[i]);
                if (new_len > SIZE_MAX - growth - 1) {
                        if (errmsg)
                                *errmsg = strdup_safe(
                                    "URL component encoding rule: Output is "
                                    "too large.");
                        return SANITIZEC_RULE_FAILED;
                }
                new_len += growth;
        }

        if (new_len == len) {
                *result = input;
                return SANITIZEC_RULE_UNCHANGED;
        }

        if (!sanitizec_buffer_reserve(output, new_len + 1)) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "URL component encoding rule: Allocation failed.");
                return SANITIZEC_RULE_FAILED;
        }

        size_t j = 0, i = 0;
        while (i < len) {
                size_t run = i;
                while (i < len &&
                       output_size((unsigned char)input.data[i]) == 1)
                        i++;
                size_t run_len = i - run;
                if (run_len)
                        memcpy(output->data + j, input.data + run, run_len);
                j += run_len;
                if (i == len) break;

                unsigned char c   = (unsigned char)input.data[i++];
                output->data[j++] = '%';
                output->data[j++] = hex[c >> 4];
                output->data[j++] = hex[c & 0x0F];
        }

        if (!sanitizec_buffer_set_length(output, j)) {
                if (errmsg)
                        *errmsg = strdup_safe(
                            "URL component encoding rule: Allocation failed.");
                return SANITIZEC_RULE_FAILED;
        }
        *result = (sanitizec_span_t){output->data, j};
        return SANITIZEC_RULE_CHANGED;
}
