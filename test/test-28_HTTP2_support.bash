#!/bin/bash
#
# Check if HTTP/2 connections using mod_gnutls and mod_http2 work

set -e
: ${srcdir:="."}
. ${srcdir}/common.bash
netns_reexec ${@}

testdir="${srcdir}/tests/28_HTTP2_support"
TEST_NAME="$(basename ${testdir})"
. $(dirname ${0})/apache_service.bash

if [ ! -r ${AP_LIBEXECDIR}/mod_http2.so ]; then
    echo "mod_http2.so not found, skipping." 2>&1
    exit 77
elif [ "$(basename ${HTTP_CLI})" != "curl" ] \
       || ! ${HTTP_CLI} -V | grep -P '\sHTTP2($|\s)'; then
    echo "Curl not found or does not support HTTP/2, skipping." 2>&1
    exit 77
fi

function stop_server
{
    apache_service "${testdir}" "apache.conf" stop
}
apache_service "${testdir}" "apache.conf" start "${TEST_LOCK}"
trap stop_server EXIT

output="outputs/${TEST_NAME}.output"
header="outputs/${TEST_NAME}.header"
rm -f "${output}" "${header}"

URL="https://${TEST_HOST}:${TEST_PORT}/status?auto"
${HTTP_CLI} --http2 --location --verbose --cacert authority/x509.pem \
	    --dump-header "${header}" --output "${output}" "${URL}"

echo "Checking for HTTP/2 in logged header:"
grep "HTTP/2 200" "${header}"
echo "Checking for TLS session status:"
grep "Current TLS session: (TLS" "${output}"

apache_service "${testdir}" "apache.conf" stop
trap - EXIT
