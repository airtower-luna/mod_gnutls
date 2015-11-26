#!/bin/bash

# Usage: wait_pid_gone ${FILE}
#
# Wait until $FILE disappears, but no longer than $TEST_LOCK_WAIT
# seconds
function wait_pid_gone
{
    local pid_file="${1}"
    local pid_wait=0
    while [ -e "${pid_file}" ]; do
	if [ "$((pid_wait++))" -gt "${TEST_LOCK_WAIT}" ]; then
	    return 1
	fi
	sleep 1
    done
}
