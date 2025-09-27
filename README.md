# sanitizec

<img width="250" height="250" alt="sanitizeC" src="https://github.com/user-attachments/assets/ecbd6a93-94dc-4f54-bb35-5d3eda3bf70b" />

A minimal, rule-based C library for string sanitization in web development, designed for high performance and flexibility for C developers.

---

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


---

## Installation and Building

### Prerequisites

- C compiler (e.g., GCC or Clang)
- Ninja build system installed

---

### Build Steps

1. **Generate the build file:**

    ```sh
    chmod +x generate_build.sh
    ./generate_build.sh
    ```

2. **Compile the library:**

    ```sh
    ninja
    ```

3. **Build and run tests:**

    ```sh
    ninja test
    ./test
    ```

---

### Installation

To install the library and headers system-wide (e.g., `/usr/local/lib` and `/usr/local/include`):

```sh
chmod +x install.sh
sudo ./install.sh

```


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

