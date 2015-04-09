#!/bin/bash

set -e

testdir="./tests/23_TLS_reverse_proxy_mismatched_priorities"
. ./proxy_backend.bash

# This test checks if server and proxy priorities are applied
# properly. The proxy server requries a TLS 1.2 connection, but the
# back end server is configured not to use TLS 1.2. The proxy request
# must fail and the client must receive an error message to pass.

function stop_backend
{
    backend_apache "${dir}" "backend.conf" stop
}
backend_apache "${testdir}" "backend.conf" start "${BACKEND_LOCK}"
trap stop_backend EXIT

make -f TestMakefile t-23

backend_apache "${testdir}" "backend.conf" stop
trap - EXIT
