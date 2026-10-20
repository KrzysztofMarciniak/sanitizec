#ifndef SANITIZEC_PATTERN_H
#define SANITIZEC_PATTERN_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
        const uint16_t* transitions;
        const uint16_t* output_offsets;
        const uint8_t* output_counts;
        const uint8_t* output_lengths;
        const uint8_t* first_bytes;
        size_t state_count;
        size_t first_byte_count;
} sanitizec_pattern_automaton_t;

extern const sanitizec_pattern_automaton_t sanitizec_sql_automaton;
extern const sanitizec_pattern_automaton_t sanitizec_shell_automaton;

int sanitizec_pattern_scan(const char* input, size_t input_len,
                           const sanitizec_pattern_automaton_t* automaton,
                           unsigned char* match_lengths);

#endif
