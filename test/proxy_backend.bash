#!/bin/bash

set -e
. ${srcdir}/common.bash

function backend_apache
{
    # needed for start and stop
    dir="${1}"
    conf="${2}"
    action="${3}"
    # Needed only for start. The "lockfile" parameter is used as flock
    # lock file or PID file to watch depending on whether FLOCK is
    # set.
    lockfile="${4}"

    TEST_NAME="$(basename "${dir}")"
    (
	export TEST_NAME
	export srcdir="$(realpath ${srcdir})"
	local flock_cmd=""
	case ${action} in
	    start)
		if [ -n "${USE_TEST_NAMESPACE}" ]; then
		    echo "Using namespaces to isolate tests, no need for" \
			 "locking."
		elif [ -n "${FLOCK}" ]; then
		    flock_cmd="${FLOCK} -w ${TEST_LOCK_WAIT} ${lockfile}"
		else
		    echo "Locking disabled, using wait based on proxy PID file."
		    wait_pid_gone "${lockfile}"
		fi
		${flock_cmd} \
		    ${APACHE2} -f "$(realpath ${testdir}/${conf})" -k start || return 1
		;;
	    stop)
		${APACHE2} -f "$(realpath ${testdir}/${conf})" -k stop || return 1
		;;
	    *)
		echo "${FUNCNAME[0]}: Invalid action \"${action}\"." >&2
		exit 1
		;;
	esac
    )
}
