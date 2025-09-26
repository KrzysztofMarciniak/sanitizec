#!/bin/sh

BUILD_FILE="build.ninja"
LIB_NAME="sanitizec" 

LIB_SRCS=$(find . -type f -name "*.c" | grep -v "/test.c" | grep -v "/tests/" | sed 's/^\.\///' | tr '\n' ' ')

TEST_SRCS="test.c $(find tests -type f -name "*.c" | sed 's/^\.\///' | tr '\n' ' ')"

LIB_OBJS=$(echo $LIB_SRCS | sed 's/\.c/\.o/g')
TEST_OBJS=$(echo $TEST_SRCS | sed 's/\.c/\.o/g')

if [ -z "$LIB_SRCS" ]; then
    echo "Error: No library source files found."
    exit 1
fi

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
echo "  command = \$cc \$in \$libs -o \$out -Wl,-rpath,."
echo "  description = LINK \$out"
echo ""
echo "rule clean"
echo "  command = rm -f \`find . -name '*.o'\` *.so test"
echo "  description = CLEAN"
echo ""
echo "# --- Object File Targets ---"

ALL_SRCS="$LIB_SRCS $TEST_SRCS"
for src in $ALL_SRCS; do
    obj=$(echo $src | sed 's/\.c/\.o/g')
    echo "build $obj: cc $src"
done

echo ""
echo "# --- Library Target ---"
echo "build lib${LIB_NAME}.so: sharedlib $LIB_OBJS"

echo ""
echo "# --- Test Executable Target ---"
echo "build test: link $TEST_OBJS lib${LIB_NAME}.so"

echo ""
echo "# --- Default and Utility Targets ---"
echo "default lib${LIB_NAME}.so"
echo "build clean: clean"
} > $BUILD_FILE

echo "Successfully generated $BUILD_FILE."
