#!/bin/bash
#
# This test checks if mod_rewrite rules can detect HTTPS connections
# with "%{HTTPS}".

set -e
: ${srcdir:="."}
. ${srcdir}/common.bash
netns_reexec ${@}

testdir="${srcdir}/tests/26_redirect_HTTP_to_HTTPS"
TEST_NAME="$(basename ${testdir})"
. $(dirname ${0})/proxy_backend.bash

: ${TEST_HTTP_PORT:="9935"}
export TEST_HTTP_PORT

# "Proxy backend" functions are used to start the only instance needed
# here without "runtests". We have to override BACKEND_PID and
# BACKEND_PORT to make them match what a runtests-based test would
# use.
export BACKEND_PID="apache2.pid"
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
URL="http://${TEST_HOST}:${TEST_HTTP_PORT}/status?auto"
if [ "$(basename ${HTTP_CLI})" = "curl" ]; then
    ${HTTP_CLI} --location --cacert authority/x509.pem "${URL}" >"${output}"
elif [ "$(basename ${HTTP_CLI})" = "wget" ]; then
    ${HTTP_CLI} --ca-certificate=authority/x509.pem -O "${output}" "${URL}"
else
    echo "No HTTP client (curl or wget) found, skipping." 2>&1
    exit 77
fi

# If the request was redirected correctly, the status report lists the
# used ciphersuite.
grep "Current TLS session: (TLS" "${output}"

backend_apache "${testdir}" "apache.conf" stop
trap - EXIT
