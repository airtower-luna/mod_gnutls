#!/bin/bash

# If USE_TEST_NAMESPACE is set and MGS_NETNS_ACTIVE is not, exec into
# the Python interpreter with the given parameters inside a new
# namespace with active loopback interface and MGS_NETNS_ACTIVE
# defined.
#
# This script can be used to isolate each testcase inside its own
# network namespace. If USE_TEST_NAMESPACE is empty or unset this
# script just execs into Python, so tests do not need to distinguish
# whether to use namespaces (unless they have a separate reason to).
#
# Note that once the network is up, the exec call is wrapped in
# another user namespace to get rid of pseudo "root" access. The
# reason for this is that Apache tries to switch permissions to a
# non-root user when apparently started as root, and fails because no
# such user exists inside the namespace. Changing to a non-root user
# beforehand avoids the issue.

if [ -n "${USE_TEST_NAMESPACE}" ] && [ -z "${MGS_NETNS_ACTIVE}" ]; then
    exec "${UNSHARE}" --net --ipc -r /bin/bash -c \
	 "export MGS_NETNS_ACTIVE=1; ip link set up lo; exec ${UNSHARE} --user ${PYTHON} ${*}"
else
    exec ${PYTHON} "${@}"
fi
