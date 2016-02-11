#!/bin/bash
#
# This test checks if mod_rewrite rules can detect HTTPS connections
# with "%{HTTPS}".

set -e
: ${srcdir:="."}
. ${srcdir}/common.bash
netns_reexec ${@}

testdir="${srcdir}/tests/26_HTTPS_server_var"
TEST_NAME="$(basename ${testdir})"
. $(dirname ${0})/proxy_backend.bash

: ${TEST_HTTP_PORT:="9935"}
export TEST_HTTP_PORT

# "Proxy backend" functions are used to start the only instance needed
# here without "runtests". We have to override BACKEND_PORT to use the
# right port.
export BACKEND_PORT="${TEST_PORT}"
function stop_backend
{
    backend_apache "${testdir}" "apache.conf" stop
}
backend_apache "${testdir}" "apache.conf" start "${TEST_LOCK}"
trap stop_backend EXIT

output="outputs/${TEST_NAME}.output"
rm -f "$output"

# Send status request over HTTP. This should get redirected to HTTPS.
wget --ca-certificate=authority/x509.pem -O "${output}" \
     "http://${TEST_HOST}:${TEST_HTTP_PORT}/status?auto"

# If the request was redirected correctly, the status report lists the
# used ciphersuite.
grep "Current TLS session: (TLS" "${output}"

backend_apache "${testdir}" "apache.conf" stop
trap - EXIT
