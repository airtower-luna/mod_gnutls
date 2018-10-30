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



# Usage: verbose_log [...]
#
# If VERBOSE is not empty, write a log message prefixed with the name
# of the calling function. The function is defined to a no-op
# otherwise.
if [ -n "${VERBOSE}" ]; then
    function verbose_log
    {
	echo "${FUNCNAME[1]}: ${@}"
    }
else
    function verbose_log
    {
	return
    }
fi



# Usage: wait_ready COMMAND [TIMEOUT] [STEP]
#
# Wait until COMMAND terminates with success (zero exit code), or
# until the TIMEOUT (in milliseconds) expires. TIMEOUT defaults to
# $TEST_SERVICE_MAX_WAIT if unset. A TIMEOUT of zero means to try
# once.
#
# COMMAND is retried every STEP milliseconds, the default is
# $TEST_SERVICE_WAIT. Note that the last try may happen a little after
# TIMEOUT expires if STEP does not evenly divide it.
function wait_ready
{
    local command="${1}"
    if [ -z "${2}" ]; then
	local -i timeout="${TEST_SERVICE_MAX_WAIT}"
    else
	local -i timeout="${2}"
    fi
    local -i step="${3}"
    [ ${step} -gt 0 ] || step="${TEST_SERVICE_WAIT}"
    # convert step to seconds because that's what "sleep" needs
    local sec_step="$((${step} / 1000)).$((${step} % 1000))"

    verbose_log "Waiting for \"${command}\" ..."
    local -i waited=0
    until eval "${command}"; do
	if [ "${waited}" -ge "${timeout}" ]; then
	    echo "${FUNCNAME[0]}: Timed out waiting for \"${command}\"" \
		 "to succeed (waited ${waited} ms)." >&2
	    return 1
	fi
	waited=$((waited + step));
	sleep "${sec_step}"
	verbose_log "waiting (${waited} ms)"
    done
    verbose_log "done (waited ${waited} ms)"
}



# Usage: netns_reexec ${@}
#
# If USE_TEST_NAMESPACE is set and MGS_NETNS_ACTIVE is not, exec the
# running command inside a new namespace with active loopback
# interface and MGS_NETNS_ACTIVE defined. This function can be used to
# isolate each testcase inside its own network namespace. Since
# MGS_NETNS_ACTIVE is used to track status, there's no harm in calling
# it multiple times (e.g. in the test-* script and runtests).
#
# Note that once the network is up, the reexec is wrapped in another
# user namespace to get rid of pseudo "root" access. The reason for
# this is that Apache tries to switch permissions to a non-root user
# when apparently started as root, and fails because no such user
# exists inside the namespace. Changing to a non-root user beforehand
# avoids that issue.
function netns_reexec
{
    if [ -n "${USE_TEST_NAMESPACE}" ] && [ -z "${MGS_NETNS_ACTIVE}" ]; then
	exec "${UNSHARE}" --net --ipc -r /bin/bash -c \
	     "export MGS_NETNS_ACTIVE=1; ip link set up lo; exec ${UNSHARE} --user ${0} ${@}"
    fi
    return 0
}
