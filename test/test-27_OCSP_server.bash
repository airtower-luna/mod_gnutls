#!/bin/bash

# Skip if OCSP tests are not enabled
[ -n "${OCSP_PORT}" ] || exit 77

. ${srcdir}/netns_py.bash ${srcdir}/runtest.py --test-number 27
