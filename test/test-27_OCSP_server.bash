#!/bin/bash
# Try HTTPS access with OCSP status check

# Skip if OCSP tests are not enabled
[ -n "${OCSP_PORT}" ] || exit 77

: ${srcdir:="."}
. ${srcdir}/common.bash
netns_reexec ${@}

. $(dirname ${0})/proxy_backend.bash

testdir="${srcdir}/tests/27_OCSP_server"
TEST_NAME="$(basename ${testdir})"

backend_apache "${testdir}" "ocsp.conf" start "${OCSP_LOCK}"

# trigger OCSP server test in the runtests script
export CHECK_OCSP_SERVER="true"
echo "OCSP index for the test CA:"
cat authority/ocsp_index.txt

${srcdir}/runtests t-27
ret=${?}

backend_apache "${testdir}" "ocsp.conf" stop

echo "Checking if client actually got a stapled response."
if grep -P "^- Options: .*OCSP status request," outputs/27_*.output; then
    echo "OK"
else
    echo "Error: \"OCSP status request\" option is missing!"
    ret=1
fi

exit ${ret}
