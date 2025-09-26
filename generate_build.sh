#!/bin/sh
# generate_build.sh - Generates the build.ninja file dynamically based on project structure.

BUILD_FILE="build.ninja"
LIB_NAME="sanitizec" # Updated library base name

# Find all C source files (excluding the test file for library compilation)
LIB_SRCS=$(find . -type f -name "*.c" | grep -v "/test.c" | sed 's/^\.\///' | tr '\n' ' ')
TEST_SRCS="test.c"

# Convert source list to object file list
LIB_OBJS=$(echo $LIB_SRCS | sed 's/\.c/\.o/g')
TEST_OBJS="test.o"

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
echo "  command = \$cc \$in \$libs -o \$out"
echo "  description = LINK \$out"
echo ""
# FIX: Using backticks for the shell command inside ninja rule for better compatibility.
echo "rule clean"
echo "  command = rm -f \`find . -name '*.o'\` *.so test"
echo "  description = CLEAN"
echo ""
echo "# --- Object File Targets ---"

# Build all object files
for src in $LIB_SRCS $TEST_SRCS; do
    # Ninja needs the output object path
    obj=$(echo $src | sed 's/\.c/\.o/g')
    # Correcting the path for the main library object if it matches the name change
    if [ "$src" = "sanitizerc.c" ]; then
        # Ensure we look for and build the actual source file name,
        # which is still 'sanitizerc.c' but the library output name is 'sanitizec'
        # To simplify, I'll rely on the object names being derived from the source file names:
        # e.g., sanitizerc.c -> sanitizerc.o
        obj=$(echo $src | sed 's/\.c/\.o/g')
        echo "build $obj: cc $src"
    else
        echo "build $obj: cc $src"
    fi
done

echo ""
echo "# --- Library Target ---"
# Output shared library name: libsanitizec.so
echo "build lib${LIB_NAME}.so: sharedlib $LIB_OBJS"

echo ""
echo "# --- Test Executable Target ---"
# Link against libsanitizec.so
echo "build test: link $TEST_OBJS lib${LIB_NAME}.so"

echo ""
echo "# --- Default and Utility Targets ---"
echo "default lib${LIB_NAME}.so"
echo "build clean: clean"
} > $BUILD_FILE

echo "Successfully generated $BUILD_FILE."
