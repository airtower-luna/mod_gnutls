#!/bin/bash

set -e

testdir="./tests/21_TLS_reverse_proxy_wrong_cert"
. ./proxy_backend.bash

function stop_backend
{
    backend_apache "${dir}" "backend.conf" stop
}
backend_apache "${testdir}" "backend.conf" start "${BACKEND_LOCK}"
trap stop_backend EXIT

make -f TestMakefile t-21

backend_apache "${testdir}" "backend.conf" stop
trap - EXIT
