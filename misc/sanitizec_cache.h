#ifndef SANITIZEC_CACHE_H
#define SANITIZEC_CACHE_H

#include <stddef.h>

#if defined(__GNUC__) || defined(__clang__)
#define SANITIZEC_CACHE_INTERNAL __attribute__((visibility("hidden")))
#else
#define SANITIZEC_CACHE_INTERNAL
#endif

#define SANITIZEC_CACHE_MAX_BYTES ((size_t)1024 * 1024)

SANITIZEC_CACHE_INTERNAL char* sanitizec_cache_get(const char* input,
                                                   int ruleset);
SANITIZEC_CACHE_INTERNAL void sanitizec_cache_store(const char* input,
                                                    int ruleset,
                                                    const char* output);

#endif
