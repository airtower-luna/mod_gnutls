#!/bin/bash

set -e
: ${srcdir:="."}

testdir="${srcdir}/tests/20_TLS_reverse_proxy_client_auth"
. $(dirname ${0})/proxy_backend.bash

function stop_backend
{
    backend_apache "${dir}" "backend.conf" stop
}
backend_apache "${testdir}" "backend.conf" start "${BACKEND_LOCK}"
trap stop_backend EXIT

make -f $(dirname ${0})/TestMakefile t-20

backend_apache "${testdir}" "backend.conf" stop
trap - EXIT
