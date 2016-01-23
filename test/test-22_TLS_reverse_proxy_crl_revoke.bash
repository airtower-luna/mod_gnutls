#!/bin/bash

set -e
: ${srcdir:="."}
. ${srcdir}/common.bash
netns_reexec ${@}

testdir="${srcdir}/tests/22_TLS_reverse_proxy_crl_revoke"
. $(dirname ${0})/proxy_backend.bash

function stop_backend
{
    backend_apache "${dir}" "backend.conf" stop
}
backend_apache "${testdir}" "backend.conf" start "${BACKEND_LOCK}"
trap stop_backend EXIT

${srcdir}/runtests t-22

backend_apache "${testdir}" "backend.conf" stop
trap - EXIT
