#!/bin/bash
set -e
${srcdir}/runtests t-14

t="$(basename ${0} .bash)"
output="outputs/${t#test-}.output"
echo "Checking if the session was resumed successfully..."
grep "This is a resumed session" "${output}" \
	|| grep "Resume Handshake was completed"  "${output}"
