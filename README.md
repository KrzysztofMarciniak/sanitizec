# sanitizec

<img width="250" height="250" alt="sanitizeC" src="https://github.com/user-attachments/assets/ecbd6a93-94dc-4f54-bb35-5d3eda3bf70b" />

A minimal, rule-based C library for string sanitization in web development, designed for high performance and flexibility for C developers.

---

## Integration Example

**An example usage of this tool:** [example-login-c-stack](https://github.com/KrzysztofMarciniak/example-login-c-stack).

## Features

- Lightweight and easy to integrate
- Supports multiple sanitization rules that can be combined using bitmasks
- Focused on common web security concerns: XSS, SQL Injection, Directory Traversal, etc.
- Efficient string manipulation with minimal overhead

---

## Available Sanitization Rules

| Rule Name           | Bitmask                      | Description                                                                                  | Example                                   |
|---------------------|------------------------------|----------------------------------------------------------------------------------------------|-------------------------------------------|
| **XSS Escape**      | `SANITIZEC_RULE_XSS_ESCAPE`  | Escapes HTML characters (`<`, `>`, `&`, `"`, `'`) to prevent Cross-Site Scripting (XSS).     | `"<script>alert('xss');</script>"` → `"&lt;script&gt;alert(&#39;xss&#39;);&lt;/script&gt;"` |
| **Trim Whitespace**  | `SANITIZEC_RULE_WHITESPACE_TRIM` | Removes leading and trailing whitespace from a string.                                       | `"  Hello World  "` → `"Hello World"`    |
| **Alpha Only**       | `SANITIZEC_RULE_ALPHA_ONLY`  | Filters out all characters that are not alphabetic letters (A-Z, a-z).                        | `"User-123_Name"` → `"UserName"`          |
| **Numeric Only**     | `SANITIZEC_RULE_NUMERIC_ONLY`| Filters out all characters that are not numeric digits (0-9).                                | `"Price: $12.50"` → `"1250"`              |
| **Alphanumeric Only**| `SANITIZEC_RULE_ALPHANUMERIC_ONLY` | Filters out all characters that are not alphanumeric (A-Z, a-z, 0-9).                        | `"User-Name: JohnDoe_123!"` → `"UserNameJohnDoe123"` |
| **LFI**              | `SANITIZEC_RULE_LFI`         | Removes `../` and `..` to prevent directory traversal in file paths.                         | `"../../etc/passwd"` → `"/etc/passwd"`   |
| **SQL**              | `SANITIZEC_RULE_SQL`         | Removes common SQL keywords to mitigate SQL injection attacks.                               | `"1 OR 1=1; --"` → `"1 OR ; --"`          |
| **Reverse Shell**    | `SANITIZEC_RULE_REVERSE_SHELL`| Removes keywords associated with reverse shell commands.                                    | `"; nc 127.0.0.1 4444 -e /bin/sh"` → `";  4444 -e bin"` |
| **Alphanumeric w/ Spaces** | `SANITIZEC_RULE_ALPHANUMERIC_WITH_SPACES_ONLY` | Alphanumeric but with spaces. | `"; Hello World$123!"` → `" Hello World123"` |
| **Hex Only** | `SANITIZEC_RULE_HEX_ONLY` | hex letters only | `"DE-AD-BE-EF! xyz@123"` → `"DEADBEEF123"` |
| **URL Component Encode** | `SANITIZEC_RULE_URL_COMPONENT_ENCODE` | Percent-encodes UTF-8 bytes using RFC 3986, leaving only unreserved characters (`A-Z`, `a-z`, `0-9`, `-`, `.`, `_`, `~`) unchanged. Existing percent sequences are encoded again. | `"a b/c"` → `"a%20b%2Fc"` |
| **Printable ASCII Only** | `SANITIZEC_RULE_ASCII_PRINTABLE_ONLY` | Keeps printable ASCII bytes (`0x20`–`0x7E`), removing control and non-ASCII bytes. | `"A\tB é"` → `"AB "` |
| **Alphanumeric, Underscore, and Hyphen Only** | `SANITIZEC_RULE_ALPHANUMERIC_WITH_UNDERSCORE_HYPHEN_ONLY` | Keeps ASCII letters, digits, `_`, and `-`. | `"User_Name-123!"` → `"User_Name-123"` |
| **Email Character Allowlist** | `SANITIZEC_RULE_EMAIL_ALLOWED_CHARS` | Keeps only ASCII letters, digits, `.`, `_`, `%`, `+`, `-`, and `@`. This filters characters; it does **not** validate email syntax or make an address safe for any particular context. | `"alice+tag@example.com!"` → `"alice+tag@example.com"` |

Rules can be combined using the bitmask API; transformations run in the dispatcher order shown in the source, so encoders and filters may change one another's output. Use URL component encoding only for an individual URL component, not for an entire URL or as a substitute for context-specific output encoding.

---

## Installation and Building

### Prerequisites

- C compiler (e.g., GCC or Clang)
- GNU Make or Ninja installed

---

### Build Steps

Choose either build system.

**GNU Make:**

```sh
make
make test
make check
```

`make test` builds the test runner; `make check` builds and runs it.
The default optimization flags are `-O3`. Override `OPTFLAGS` or supply
`ARCHFLAGS` for optional host-specific tuning; for example,
`make OPTFLAGS=-O3 ARCHFLAGS=-march=native`. Native tuning can make the library
incompatible with other CPU models. `CFLAGS`, `CPPFLAGS`, and `THREAD_FLAGS`
remain configurable, as do `LDFLAGS` and `LDLIBS`. Runtime memoization is off by
default because it slows unique-input workloads; enable it for repetition-heavy
workloads with `make CACHE=1`. The cache is process-local, thread-safe, and
limited to a nominal 1 MiB including index and entry metadata (allocator
overhead excluded). It retains cached input/output bytes until eviction or
process exit. Make tracks build-flag changes and rebuilds affected objects
automatically. Use `make CACHE=1 install` to install a memoization-enabled build.

Run all benchmark cases with:

```sh
make benchmark
# or
./bench/run.sh
```

The runner reports short repeated/unique inputs and large repeated/unique
payloads, with elapsed time, calls per second, and input throughput. To measure
the optional memoization build, use `make CACHE=1 benchmark`; compare multiple
runs on the same machine because these numbers are workload- and system-specific.

**Ninja:**

```sh
./generate_build.sh
ninja
ninja test
./test
```

The Ninja generator uses the same `OPTFLAGS`, `ARCHFLAGS`, `CFLAGS`,
`CPPFLAGS`, `LDFLAGS`, `LDLIBS`, and `THREAD_FLAGS` environment variables as
Make, plus `CACHE=1` to enable runtime memoization, for example:
`OPTFLAGS=-O3 ARCHFLAGS=-march=native CACHE=1 ./generate_build.sh`.

---

### Installation

To install the library and header system-wide (e.g., `/usr/local/lib` and `/usr/local/include`):

```sh
sudo make install
```

Set `PREFIX` to change the installation prefix, or `DESTDIR` to stage an installation.

#### Example Usage

``` c
#include <stdio.h>
#include <stdlib.h>
#include <sanitizec.h>

int main() {
    const char* input_string = "My product ID is #987654321!";
    char* error_message = NULL;
                                        //You can choose whatever rule you want here:
    char* sanitized_output = sanitizec_apply(input_string, SANITIZEC_RULE_NUMERIC_ONLY, &error_message);

    if (sanitized_output) {
        printf("Original: %s\n", input_string); // 'My product ID is #987654321!'
        printf("Sanitized: %s\n", sanitized_output); // '987654321'
        free(sanitized_output); 
    } else {
        fprintf(stderr, "Error: %s\n", error_message);
        if (error_message) {
            free(error_message);
        }
    }

    return 0;
}

```
