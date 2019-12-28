#!/bin/bash
set -e

# output files, needed for post_check hook
log="outputs/16_view-status.log"
output="outputs/16_view-status.output"

. ${srcdir}/netns_py.bash ${srcdir}/runtest.py --test-number 16 \
	--log-connection "${log}" --log-responses "${output}"
