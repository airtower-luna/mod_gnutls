#!/bin/bash
export USE_MSVA="yes"
. ${srcdir}/netns_py.bash ${srcdir}/runtest.py --test-number 15
