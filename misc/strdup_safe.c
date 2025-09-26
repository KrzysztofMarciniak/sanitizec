#include "strdup_safe.h"

#include <stdlib.h>
#include <string.h>

/**
 * @brief Duplicates a string and returns it, handling allocation failure.
 */
extern char* strdup_safe(const char* s) {
        size_t len = strlen(s) + 1;
        char* p    = malloc(len);
        if (p) {
                memcpy(p, s, len);
        }
        return p;
}
