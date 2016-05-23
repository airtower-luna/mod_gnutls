#!/bin/bash
# Try HTTPS access with OCSP status check

# Skip if OCSP tests are not enabled
[ -n "${OCSP_PORT}" ] || exit 77

# trigger OCSP server test in the runtests script
export CHECK_OCSP_SERVER="true"

${srcdir}/runtests t-27
