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



# Usage: netns_reexec ${@}
#
# If USE_TEST_NAMESPACE is set and MGS_NETNS_ACTIVE is not, exec the
# running command inside a new namespace with active loopback
# interface and MGS_NETNS_ACTIVE defined. This function can be used to
# isolate each testcase inside its own network namespace. Since
# MGS_NETNS_ACTIVE is used to track status, there's no harm in calling
# it multiple times (e.g. in the test-* script and runtests).
function netns_reexec
{
    if [ -n "${USE_TEST_NAMESPACE}" ] && [ -z "${MGS_NETNS_ACTIVE}" ]; then
	exec "${UNSHARE}" --net -r /bin/bash -c \
	     "export MGS_NETNS_ACTIVE=1; ip link set up lo; exec ${0} ${@}"
    fi
    return 0
}
