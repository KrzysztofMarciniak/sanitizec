### sanitizec

A small, minimal C library for string sanitization in web development, focused on performance and flexibility for C developers.
Features

- Lightweight: Minimal dependencies, ideal for embedded or performance-critical applications.

- Configurable: Choose from built-in rulesets or create your own custom combinations using a bitmask.

- Built-in Rules:
...
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

Note: If successful, the library will be installed as /usr/local/lib/libsanitizec.so and the header as /usr/local/include/sanitizec.h.

#### Usage...

