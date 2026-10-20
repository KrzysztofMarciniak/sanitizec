#!/bin/sh

BUILD_FILE="build.ninja"
LIB_NAME="sanitizec" 

CC=${CC:-cc}
CPPFLAGS=${CPPFLAGS:--I.}
CFLAGS=${CFLAGS:--Wall -Wextra}
OPTFLAGS=${OPTFLAGS:--O3}
ARCHFLAGS=${ARCHFLAGS:-}
LDFLAGS=${LDFLAGS:-}
LDLIBS=${LDLIBS:-}
THREAD_FLAGS=${THREAD_FLAGS:--pthread}
CACHE=${CACHE:-0}
CACHE_FLAGS=
if [ "$CACHE" = "1" ]; then
    CACHE_FLAGS=-DSANITIZEC_ENABLE_CACHE
fi

LIB_SRCS=$(find . -type f -name "*.c" | grep -v "/test.c" | grep -v "/tests/" | grep -v "/misc/sanitizec_cache.c" | sed 's/^\.\///' | tr '\n' ' ')
if [ "$CACHE" = "1" ]; then
    LIB_SRCS="$LIB_SRCS misc/sanitizec_cache.c"
fi

TEST_SRCS="test.c $(find tests -type f -name "*.c" | sed 's/^\.\///' | tr '\n' ' ')"

LIB_OBJS=$(echo $LIB_SRCS | sed 's/\.c/\.o/g')
TEST_OBJS=$(echo $TEST_SRCS | sed 's/\.c/\.o/g')

if [ -z "$LIB_SRCS" ]; then
    echo "Error: No library source files found."
    exit 1
fi

{
echo "cc = $CC"
echo "ranlib = ranlib"
echo ""
echo "# Override CPPFLAGS, OPTFLAGS, ARCHFLAGS, CFLAGS, LDFLAGS, LDLIBS, THREAD_FLAGS, and CACHE."
echo "cflags = $CPPFLAGS $OPTFLAGS $ARCHFLAGS $CFLAGS $CACHE_FLAGS -fPIC $THREAD_FLAGS"
echo "ldflags = $LDFLAGS $THREAD_FLAGS"
echo "sharedflags = -shared $LDFLAGS $THREAD_FLAGS"
echo "libs = $LDLIBS"
echo ""
echo "rule cc"
echo "  command = \$cc \$cflags -c \$in -o \$out"
echo "  description = CC \$in"
echo ""
echo "rule sharedlib"
echo "  command = \$cc \$sharedflags -o \$out \$in \$libs"
echo "  description = SHAREDLIB \$out"
echo ""
echo "rule link"
echo "  command = \$cc \$ldflags \$in \$libs -o \$out -Wl,-rpath,."
echo "  description = LINK \$out"
echo ""
echo "rule clean"
echo "  command = rm -f \`find . -name '*.o'\` *.so test test-runner"
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
