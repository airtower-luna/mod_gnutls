#!/bin/bash
set -e
${srcdir}/runtests t-14

t="$(basename ${0} .bash)"
output="outputs/${t#test-}.output"
echo "Checking if the session was resumed successfully..."
# NOTE: The "Resume Handshake was completed" message appears after the
# second handshake is complete, whether the session has been resumed
# or not. The following message is required!
grep "This is a resumed session" "${output}"
