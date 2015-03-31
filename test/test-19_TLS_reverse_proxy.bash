#!/bin/bash

set -e

testdir="./tests/19_TLS_reverse_proxy"
. ./proxy_backend.bash

function stop_backend
{
    backend_apache "${dir}" "backend.conf" stop
}
backend_apache "${testdir}" "backend.conf" start "${BACKEND_LOCK}"
trap stop_backend EXIT

make -f TestMakefile t-19

backend_apache "${testdir}" "backend.conf" stop
trap - EXIT
