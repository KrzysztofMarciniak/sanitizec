#include "sanitizec_buffer.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void sanitizec_buffer_init(sanitizec_buffer_t* buffer) {
        buffer->data       = buffer->inline_data;
        buffer->length     = 0;
        buffer->capacity   = sizeof(buffer->inline_data);
        buffer->force_heap = 0;
        buffer->data[0]    = '\0';
}

void sanitizec_buffer_reset(sanitizec_buffer_t* buffer) {
        buffer->length     = 0;
        buffer->force_heap = 0;
        buffer->data[0]    = '\0';
}

void sanitizec_buffer_destroy(sanitizec_buffer_t* buffer) {
        if (buffer->data != buffer->inline_data) free(buffer->data);
        sanitizec_buffer_init(buffer);
}

int sanitizec_buffer_reserve(sanitizec_buffer_t* buffer,
                             size_t required_capacity) {
        if (required_capacity <= buffer->capacity &&
            (!buffer->force_heap || buffer->data != buffer->inline_data)) {
                return 1;
        }

        size_t new_capacity = required_capacity;
        if (!buffer->force_heap) {
                new_capacity = buffer->capacity;
                while (new_capacity < required_capacity) {
                        if (new_capacity > SIZE_MAX / 2) {
                                new_capacity = required_capacity;
                                break;
                        }
                        new_capacity *= 2;
                }
        }

        char* new_data;
        if (buffer->data == buffer->inline_data) {
                new_data = (char*)malloc(new_capacity);
                if (!new_data) return 0;
                memcpy(new_data, buffer->data, buffer->length + 1);
        } else {
                new_data = (char*)realloc(buffer->data, new_capacity);
                if (!new_data) return 0;
        }

        buffer->data     = new_data;
        buffer->capacity = new_capacity;
        return 1;
}

int sanitizec_buffer_set_length(sanitizec_buffer_t* buffer, size_t length) {
        if (length >= buffer->capacity) return 0;
        buffer->length       = length;
        buffer->data[length] = '\0';
        return 1;
}

void sanitizec_buffer_force_heap(sanitizec_buffer_t* buffer) {
        buffer->force_heap = 1;
}

char* sanitizec_buffer_take_string(sanitizec_buffer_t* buffer) {
        if (buffer->data != buffer->inline_data) {
                char* result       = buffer->data;
                buffer->data       = buffer->inline_data;
                buffer->length     = 0;
                buffer->capacity   = sizeof(buffer->inline_data);
                buffer->force_heap = 0;
                buffer->data[0]    = '\0';
                return result;
        }

        char* result = (char*)malloc(buffer->length + 1);
        if (!result) return NULL;
        memcpy(result, buffer->data, buffer->length + 1);
        return result;
}
