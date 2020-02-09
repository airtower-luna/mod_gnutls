# Copyright 2020 Fiona Klute
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Helpers for Valgrind tests."""

import re

err_re = re.compile(r'^==\d+== ERROR SUMMARY: (\d+) errors from '
                    r'\d+ contexts \(suppressed: (\d+) from \d+\)')

def error_summary(log):
    """Read all available error summaries from the given log (open text
    file).

    Returns a tuple of two ints, containing the number of reported and
    suppressed errors, in that order.

    """
    # reported errors, suppressed errors
    errors = (0, 0)
    for line in log:
        m = err_re.match(line)
        if m:
            add = (int(m.group(1)), int(m.group(2)))
            errors = tuple(sum(x) for x in zip(errors, add))
    return errors
