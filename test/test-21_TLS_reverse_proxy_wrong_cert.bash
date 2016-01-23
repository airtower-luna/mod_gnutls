#!/bin/bash

set -e
: ${srcdir:="."}
. ${srcdir}/common.bash
netns_reexec ${@}

testdir="${srcdir}/tests/21_TLS_reverse_proxy_wrong_cert"
. $(dirname ${0})/proxy_backend.bash

function stop_backend
{
    backend_apache "${dir}" "backend.conf" stop
}
backend_apache "${testdir}" "backend.conf" start "${BACKEND_LOCK}"
trap stop_backend EXIT

${srcdir}/runtests t-21

backend_apache "${testdir}" "backend.conf" stop
trap - EXIT
