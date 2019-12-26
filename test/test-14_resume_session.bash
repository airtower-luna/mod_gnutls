#!/bin/bash
set -e
log="outputs/14_resume_session.log"

${srcdir}/netns_py.bash ${srcdir}/runtest.py --test-number 14 \
	--log-connection "${log}"

echo "Checking if the session was resumed successfully..."
# NOTE: The "Resume Handshake was completed" message appears after the
# second handshake is complete, whether the session has been resumed
# or not. The following message is required!
grep "This is a resumed session" "${log}"
