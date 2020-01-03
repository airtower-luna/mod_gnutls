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

. ${srcdir}/netns_py.bash ${srcdir}/runtest.py --test-number 28
