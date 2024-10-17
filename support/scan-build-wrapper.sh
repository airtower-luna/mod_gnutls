#!/bin/sh

# find the current default LLVM version and its scan-build-py
llvm_version="$(readlink $(command -v scan-build) | cut -d '-' -f 3)"
SCAN_BUILD_PY="$(command -v scan-build-py-${llvm_version})"

# run it to produce SARIF and HTML output with Clang
exec "${SCAN_BUILD_PY}" --sarif-html --use-cc=clang "$@"
