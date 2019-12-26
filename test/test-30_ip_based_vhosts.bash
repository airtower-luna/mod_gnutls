#!/bin/bash

# Parse TEST_IP into an array
declare -a addrs=(${TEST_IP})
if [ ${#addrs[@]} -lt 2 ]; then
    echo "This test needs two or more IP addresses in TEST_IP," \
	 "check ./configure options!"
    exit 77
fi

# The two virtual hosts have different IPs, so we can check if
# selection without SNI works correctly. The request will go to the
# second one.
export VHOST1_IP="${addrs[0]}"
export VHOST2_IP="${addrs[1]}"

# gnutls-cli expects IPv6 addresses without enclosing brackets, remove
# them
TARGET_IP="${VHOST2_IP#\[}"
TARGET_IP="${TARGET_IP%\]}"
export TARGET_IP

. ${srcdir}/netns_py.bash ${srcdir}/runtest.py --test-number 30
