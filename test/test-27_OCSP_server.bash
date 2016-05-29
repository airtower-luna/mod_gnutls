#!/bin/bash
# Try HTTPS access with OCSP status check

# Skip if OCSP tests are not enabled
[ -n "${OCSP_PORT}" ] || exit 77

# trigger OCSP server test in the runtests script
export CHECK_OCSP_SERVER="true"
export OCSP_RESPONSE_FILE="$(mktemp mod_gnutls_test-XXXXXX.der)"

${srcdir}/runtests t-27

ocsptool -e --load-signer authority/x509.pem --load-response ${OCSP_RESPONSE_FILE} || ret=1
rm "${OCSP_RESPONSE_FILE}"
exit ${ret}
