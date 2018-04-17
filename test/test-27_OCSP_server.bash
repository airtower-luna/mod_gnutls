#!/bin/bash
# Try HTTPS access with OCSP status check

# Skip if OCSP tests are not enabled
[ -n "${OCSP_PORT}" ] || exit 77

${srcdir}/runtests t-27
ret=${?}

echo "Checking if client actually got a stapled response."
if grep -P "^- Options: .*OCSP status request," outputs/27_*.output; then
    echo "OK"
else
    echo "Error: \"OCSP status request\" option is missing!"
    ret=1
fi

exit ${ret}
