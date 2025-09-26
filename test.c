#include "sanitizec.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    const char* test_input_1 = "<h1>Hello, World! <script>bad()</script></h1>";
    const char* test_input_2 = "SELECT * FROM users WHERE name='O\'Malley';";

    printf("--- sanitizerc Test Program ---\n\n");

    // Test 1: Web Safe Ruleset
    printf("Input 1 (Web): %s\n", test_input_1);
    char* safe_web = sanitizec_apply(test_input_1, SANITIZEC_RULESET_WEB_SAFE);

    if (safe_web) {
        printf("Output 1 (Web): %s\n", safe_web);
        free(safe_web);
    } else {
        fprintf(stderr, "Test 1 failed to allocate memory.\n");
    }

    printf("\n");

    // Test 2: DB Safe Ruleset
    printf("Input 2 (DB): %s\n", test_input_2);
    char* safe_db = sanitizec_apply(test_input_2, SANITIZEC_RULESET_DB_SAFE);

    if (safe_db) {
        printf("Output 2 (DB): %s\n", safe_db);
        free(safe_db);
    } else {
        fprintf(stderr, "Test 2 failed to allocate memory.\n");
    }

    printf("\n--- Test complete ---\n");

    return 0;
}
