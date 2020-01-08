#!/bin/bash
#
# This test checks if mod_rewrite rules can detect HTTPS connections
# with "%{HTTPS}".
. ${srcdir}/netns_py.bash ${srcdir}/runtest.py --test-number 26
