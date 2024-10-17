#!/bin/sh
# run cppcheck using the project config created by Meson, write output
# to build dir
CPPCHECK_DIR="${MESON_BUILD_ROOT}/cppcheck"
mkdir -p "${CPPCHECK_DIR}"
cppcheck --project="${MESON_BUILD_ROOT}/compile_commands.json" \
	--cppcheck-build-dir="${CPPCHECK_DIR}" \
	-DAF_UNIX=1 \
	--enable=warning,style \
	"$@"
