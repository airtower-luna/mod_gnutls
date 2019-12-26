#!/bin/bash
#
# This test checks if mod_rewrite rules can detect HTTPS connections
# with "%{HTTPS}".

: ${TEST_HTTP_PORT:="9935"}
export TEST_HTTP_PORT

. ${srcdir}/netns_py.bash ${srcdir}/runtest.py --test-number 26
