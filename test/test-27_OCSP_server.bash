#!/bin/bash
# Try HTTPS access with OCSP status check

# Skip if OCSP tests are not enabled
[ -n "${OCSP_PORT}" ] || exit 77

log="outputs/27_OCSP_server.log"
${srcdir}/netns_py.bash ${srcdir}/runtest.py --test-number 27 \
	 --log-connection "${log}"
ret=${?}

echo "Checking if client actually got a stapled response."
if grep -P "^- Options: .*OCSP status request," "${log}"; then
    echo "OK"
else
    echo "Error: \"OCSP status request\" option is missing!"
    ret=1
fi

exit ${ret}
