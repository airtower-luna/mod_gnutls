#!/bin/sh

bin="scan-build-py"
SCAN_BUILD_PY="$(command -v ${bin})"
if [ -z "${SCAN_BUILD_PY}" ]; then
    # find the current default LLVM version and its scan-build-py
    llvm_version="$(readlink $(command -v scan-build) | cut -d '-' -f 3)"
    SCAN_BUILD_PY="$(command -v ${bin}-${llvm_version})"
fi

if [ -z "${SCAN_BUILD_PY}" ]; then
    echo "ERROR: ${bin} not found!" >&2
    exit 1
fi

# run it to produce SARIF and HTML output with Clang
exec "${SCAN_BUILD_PY}" --sarif-html --use-cc=clang "$@"
