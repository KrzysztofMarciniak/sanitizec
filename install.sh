#!/bin/sh
set -xe

make install
command -v ldconfig >/dev/null && ldconfig || true
