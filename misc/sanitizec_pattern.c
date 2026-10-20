#include "sanitizec_pattern.h"

#include <string.h>

#if defined(__SSE2__)
#include <emmintrin.h>
#endif

#include "sanitizec_patterns.generated.h"

static unsigned char normalize(unsigned char c) {
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + ('a' - 'A'));
        return c;
}

static size_t find_next_start(const unsigned char* input, size_t len,
                              const uint8_t* starts, size_t start_count) {
        size_t i = 0;
#if defined(__SSE2__)
        const __m128i lowercase_bit = _mm_set1_epi8(0x20);
        while (len - i >= 16) {
                __m128i bytes   = _mm_loadu_si128((const __m128i*)(input + i));
                bytes           = _mm_or_si128(bytes, lowercase_bit);
                __m128i matches = _mm_setzero_si128();
                for (size_t j = 0; j < start_count; j++) {
                        __m128i start = _mm_set1_epi8((char)starts[j]);
                        matches =
                            _mm_or_si128(matches, _mm_cmpeq_epi8(bytes, start));
                }
                unsigned int mask = (unsigned int)_mm_movemask_epi8(matches);
                if (mask) return i + (size_t)__builtin_ctz(mask);
                i += 16;
        }
#endif
        for (; i < len; i++) {
                unsigned char c = normalize(input[i]);
                for (size_t j = 0; j < start_count; j++) {
                        if (c == starts[j]) return i;
                }
        }
        return len;
}

int sanitizec_pattern_scan(const char* input, size_t input_len,
                           const sanitizec_pattern_automaton_t* automaton,
                           unsigned char* match_lengths) {
        const unsigned char* bytes = (const unsigned char*)input;
        size_t position            = 0;
        uint16_t state             = 0;
        int matched                = 0;

        while (position < input_len) {
                if (state == 0) {
                        size_t next = find_next_start(
                            bytes + position, input_len - position,
                            automaton->first_bytes,
                            automaton->first_byte_count);
                        if (next == input_len - position) break;
                        position += next;
                }

                unsigned char c = normalize(bytes[position]);
                state         = automaton->transitions[(size_t)state * 256 + c];
                uint8_t count = automaton->output_counts[state];
                uint16_t offset = automaton->output_offsets[state];
                for (uint8_t i = 0; i < count; i++) {
                        uint8_t length = automaton->output_lengths[offset + i];
                        size_t start   = position + 1 - length;
                        if (match_lengths && match_lengths[start] < length)
                                match_lengths[start] = length;
                        matched = 1;
                }
                position++;
        }
        return matched;
}
