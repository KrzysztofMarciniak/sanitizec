### sanitizec

A small, ruled based, minimal C library for string sanitization in web development, focused on performance and flexibility for C developers.

### Available Sanitization Rules

| Rule Name | Bitmask | Description | Example |
| :--- | :--- | :--- | :--- |
| **XSS Escape** | `SANITIZEC_RULE_XSS_ESCAPE` | Escapes HTML characters (`<`, `>`, `&`, `"`, `'`) to prevent Cross-Site Scripting (XSS). | `"<script>alert('xss');</script>"` becomes `"&lt;script&gt;alert(&#39;xss&#39;);&lt;/script&gt;"` |
| **Trim Whitespace** | `SANITIZEC_RULE_WHITESPACE_TRIM` | Removes leading and trailing whitespace from a string. | `"  Hello World  "` becomes `"Hello World"` |
| **Alpha Only** | `SANITIZEC_RULE_ALPHA_ONLY` | Filters out all characters that are not alphabetic letters (A-Z, a-z). | `"User-123_Name"` becomes `"UserName"` |
| **Numeric Only** | `SANITIZEC_RULE_NUMERIC_ONLY` | Filters out all characters that are not numeric digits (0-9). | `"Price: $12.50"` becomes `"1250"` |
| **Alphanumeric Only** | `SANITIZEC_RULE_ALPHANUMERIC_ONLY` | Filters out all characters that are not alphanumeric (A-Z, a-z, 0-9). | `"User-Name: JohnDoe_123!"` becomes `"UserNameJohnDoe123"` |
| **LFI** | `SANITIZEC_RULE_LFI` | Removes `../` and `..` to prevent directory traversal in file paths. | `"/etc/passwd"` becomes `"/etc/passwd"` but `"../../etc/passwd"` becomes `"/etc/passwd"` |
| **SQL** | `SANITIZEC_RULE_SQL` | Removes common SQL keywords to mitigate SQL injection attacks. | `"1 OR 1=1; --"` becomes `"1 OR ; --"` |
| **Reverse Shell** | `SANITIZEC_RULE_REVERSE_SHELL` | Removes keywords associated with reverse shell commands. | `"; nc 127.0.0.1 4444 -e /bin/sh"` becomes `";  4444 -e bin"` |


### Installation and Building

The library uses Ninja for building, driven by a dynamically generated build.ninja file.
Prerequisites

You must have a C compiler (cc, typically GCC or Clang) and the ninja build tool installed on your system.

#### Build Steps

Run the following commands in the root directory to generate the build file, compile the library, and build the test executable:

##### 1. Generate the build file (build.ninja)

```sh
chmod +x generate_build.sh
./generate_build.sh
```

# 2. Compile the library (libsanitizec.so)

```sh
ninja 
```

# 3. Build and test the executable (uses RPATH for local testing)

```sh 
ninja test
./test
```

#### Installation

To install the library and headers system-wide (e.g., to /usr/local/lib and /usr/local/include), use the install.sh script:

```
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

