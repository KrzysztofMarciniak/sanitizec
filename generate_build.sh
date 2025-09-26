#!/bin/sh
# generate_build.sh - Generates the build.ninja file dynamically based on project structure.

BUILD_FILE="build.ninja"
LIB_NAME="sanitizec" # Updated library base name

# --- FIX START: Correctly identify all Test Source Files ---

# 1. Find all C source files that are *not* in the 'tests' directory and not the 'test.c' file.
# These files will be compiled into the library.
# We remove the leading './' from paths.
LIB_SRCS=$(find . -type f -name "*.c" | grep -v "/test.c" | grep -v "/tests/" | sed 's/^\.\///' | tr '\n' ' ')

# 2. Find all C source files for the test executable: test.c and all files in the tests/ directory.
# We remove the leading './' from paths.
TEST_SRCS="test.c $(find tests -type f -name "*.c" | sed 's/^\.\///' | tr '\n' ' ')"

# --- FIX END ---

# Convert source list to object file list
# Note: Test source objects will have paths (e.g., tests/escape_xss/escape_xss.o)
LIB_OBJS=$(echo $LIB_SRCS | sed 's/\.c/\.o/g')
# The TEST_SRCS list now contains all source files for the test executable
TEST_OBJS=$(echo $TEST_SRCS | sed 's/\.c/\.o/g')

# Check if we found any library sources
if [ -z "$LIB_SRCS" ]; then
    echo "Error: No library source files found."
    exit 1
fi

# Start generating build.ninja
{
echo "cc = cc"
echo "ranlib = ranlib"
echo ""
echo "# Compiler flags: -I. for main headers, -fPIC for shared library, -Wall/-Wextra for quality"
echo "cflags = -I. -I./rules -fPIC -Wall -Wextra" # Added -I./rules for rule headers
echo "ldflags = -shared"
echo "libs = "
echo ""
echo "rule cc"
echo "  command = \$cc \$cflags -c \$in -o \$out"
echo "  description = CC \$in"
echo ""
echo "rule sharedlib"
echo "  command = \$cc \$ldflags -o \$out \$in \$libs"
echo "  description = SHAREDLIB \$out"
echo ""
echo "rule link"
# FIX: Added -Wl,-rpath,. to embed the current directory into the executable's library search path.
echo "  command = \$cc \$in \$libs -o \$out -Wl,-rpath,."
echo "  description = LINK \$out"
echo ""
echo "rule clean"
echo "  command = rm -f \`find . -name '*.o'\` *.so test"
echo "  description = CLEAN"
echo ""
echo "# --- Object File Targets ---"

# Build all object files (Library and Test objects)
ALL_SRCS="$LIB_SRCS $TEST_SRCS"
for src in $ALL_SRCS; do
    # Ninja needs the output object path
    obj=$(echo $src | sed 's/\.c/\.o/g')
    # Use the source path directly for the CC rule
    echo "build $obj: cc $src"
done

echo ""
echo "# --- Library Target ---"
# Output shared library name: libsanitizec.so
echo "build lib${LIB_NAME}.so: sharedlib $LIB_OBJS"

echo ""
echo "# --- Test Executable Target ---"
# Link against all Test Objects AND the shared library
echo "build test: link $TEST_OBJS lib${LIB_NAME}.so"

echo ""
echo "# --- Default and Utility Targets ---"
echo "default lib${LIB_NAME}.so"
echo "build clean: clean"
} > $BUILD_FILE

echo "Successfully generated $BUILD_FILE."
