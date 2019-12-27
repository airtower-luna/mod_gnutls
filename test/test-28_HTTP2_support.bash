#!/bin/bash
#
# Check if HTTP/2 connections using mod_gnutls and mod_http2 work

set -e

if [ ! -r ${AP_LIBEXECDIR}/mod_http2.so ]; then
    echo "mod_http2.so not found, skipping." 2>&1
    exit 77
elif [ "$(basename ${HTTP_CLI})" != "curl" ] \
       || ! ${HTTP_CLI} -V | grep -P '\sHTTP2($|\s)'; then
    echo "Curl not found or does not support HTTP/2, skipping." 2>&1
    exit 77
fi

# expected output files
log="outputs/28_HTTP2_support.log"
output="outputs/28_HTTP2_support.output"

${srcdir}/netns_py.bash ${srcdir}/runtest.py --test-number 28 \
	 --log-connection "${log}" --log-responses "${output}"

echo "Checking for HTTP/2 in logged header:"
grep "HTTP/2 200" "${log}"
echo "Checking for TLS session status:"
grep "Current TLS session: (TLS" "${output}"
