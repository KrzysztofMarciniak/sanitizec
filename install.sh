#!/bin/sh
set -xe

# Project files
LIB_NAME="sanitizerc"
SHARED_LIB="lib${LIB_NAME}.so"
HEADER_FILE="${LIB_NAME}.h"

echo "Building ${LIB_NAME} (shared)..."
ninja

echo "Installing to /usr/local..."

install -Dm644 ${SHARED_LIB} /usr/local/lib/${SHARED_LIB}

install -Dm644 ${HEADER_FILE} /usr/local/include/${HEADER_NAME}

command -v ldconfig >/dev/null && ldconfig || true

echo "Installation complete!"
echo "To use: Link with -l${LIB_NAME}"
echo "Headers in /usr/local/include, lib in /usr/local/lib"
