#ifndef SANITIZEC_BUFFER_H
#define SANITIZEC_BUFFER_H

#include <stddef.h>
#include <stdint.h>

#define SANITIZEC_BUFFER_INLINE_CAPACITY 1024

typedef struct {
        char inline_data[SANITIZEC_BUFFER_INLINE_CAPACITY];
        char* data;
        size_t length;
        size_t capacity;
        int force_heap;
} sanitizec_buffer_t;

void sanitizec_buffer_init(sanitizec_buffer_t* buffer);
void sanitizec_buffer_reset(sanitizec_buffer_t* buffer);
void sanitizec_buffer_destroy(sanitizec_buffer_t* buffer);
int sanitizec_buffer_reserve(sanitizec_buffer_t* buffer,
                             size_t required_capacity);
int sanitizec_buffer_set_length(sanitizec_buffer_t* buffer, size_t length);
void sanitizec_buffer_force_heap(sanitizec_buffer_t* buffer);
char* sanitizec_buffer_take_string(sanitizec_buffer_t* buffer);

static inline int sanitizec_buffer_append(sanitizec_buffer_t* buffer,
                                          char value) {
        if (buffer->length < buffer->capacity &&
            buffer->capacity - buffer->length > 1) {
                buffer->data[buffer->length++] = value;
                buffer->data[buffer->length]   = '\0';
                return 1;
        }

        if (buffer->length > SIZE_MAX - 2 ||
            !sanitizec_buffer_reserve(buffer, buffer->length + 2)) {
                return 0;
        }
        buffer->data[buffer->length++] = value;
        buffer->data[buffer->length]   = '\0';
        return 1;
}

#endif
