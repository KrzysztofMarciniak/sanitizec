#include <stdio.h>
#include <stdlib.h>

#include "tests/alpha_only/alpha_only.h"
#include "tests/alphanumeric_only/alphanumeric_only.h"
#include "tests/alphanumeric_with_spaces_only/alphanumeric_with_spaces_only.h"
#include "tests/alphanumeric_with_underscore_hyphen_only/alphanumeric_with_underscore_hyphen_only.h"
#include "tests/ascii_printable_only/ascii_printable_only.h"
#include "tests/email_allowed_chars/email_allowed_chars.h"
#include "tests/escape_xss/escape_xss.h"
#include "tests/hex_only/hex_only.h"
#include "tests/numeric_only/numeric_only.h"
#include "tests/sanitize_lfi/sanitize_lfi.h"
#include "tests/sanitize_reverse_shell/sanitize_reverse_shell.h"
#include "tests/sanitize_sql/sanitize_sql.h"
#include "tests/sanitizec_cache/sanitizec_cache.h"
#include "tests/trim_whitespace/trim_whitespace.h"
#include "tests/url_component_encode/url_component_encode.h"

/**
 * @brief Main test manager entry point.
 * Runs all defined test functions and reports the final count of
 * failures.
 */
int main(void) {
        int number_failed = 0;
        int total_tests   = 0;

        printf("--- Starting SanitizeC Test Manager ---\n\n");

        total_tests++;
        if (run_xss_escape_test() == 0) {
                number_failed++;
        }

        total_tests++;
        if (run_trim_whitespace_test() == 0) {
                number_failed++;
        }

        total_tests++;
        if (run_alpha_only_test() == 0) {
                number_failed++;
        }

        total_tests++;
        if (run_numeric_only_test() == 0) {
                number_failed++;
        }

        total_tests++;
        if (run_alphanumeric_only_test() == 0) {
                number_failed++;
        }

        total_tests++;
        if (run_lfi_test() == 0) {
                number_failed++;
        }

        total_tests++;
        if (run_sql_safe_test() == 0) {
                number_failed++;
        }

        total_tests++;
        if (run_reverse_shell_safe_test() == 0) {
                number_failed++;
        }
        total_tests++;
        if (run_alphanumeric_with_spaces_test() == 0) {
                number_failed++;
        }
        total_tests++;
        if (run_hex_only_test() == 0) {
                number_failed++;
        }
        total_tests++;
        if (run_url_component_encode_test() == 0) {
                number_failed++;
        }
        total_tests++;
        if (run_ascii_printable_only_test() == 0) {
                number_failed++;
        }
        total_tests++;
        if (run_alphanumeric_with_underscore_hyphen_only_test() == 0) {
                number_failed++;
        }
        total_tests++;
        if (run_email_allowed_chars_test() == 0) {
                number_failed++;
        }
        total_tests++;
        if (run_sanitizec_cache_test() == 0) {
                number_failed++;
        }
        printf("\n--- Test Manager Complete ---\n");
        printf("Total test modules run: %d\n", total_tests);
        printf("Total test modules failed: %d\n", number_failed);

        return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
