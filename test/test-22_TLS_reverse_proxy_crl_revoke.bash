#!/bin/bash

set -e

testdir="./tests/22_TLS_reverse_proxy_crl_revoke"
. ./proxy_backend.bash

# Generate CRL revoking the server certificate. Using it as
# GnuTLSProxyCRLFile should cause the connection to the back end
# server to fail.
certtool --generate-crl \
    --load-ca-privkey authority/secret.key \
    --load-ca-certificate authority/x509.pem \
    --load-certificate server/x509.pem \
    --template "${testdir}/crl.template" \
    >"${testdir}/crl.pem"

function stop_backend
{
    backend_apache "${dir}" "backend.conf" stop
}
backend_apache "${testdir}" "backend.conf" start "${BACKEND_LOCK}"
trap stop_backend EXIT

make -f TestMakefile t-22

backend_apache "${testdir}" "backend.conf" stop
trap - EXIT
