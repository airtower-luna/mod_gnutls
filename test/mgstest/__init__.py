#!/usr/bin/python3

# Copyright 2019-2020 Fiona Klute
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

"""Python modules for the mod_gnutls test suite."""

import fcntl
import os
import os.path
import sys

from contextlib import contextmanager
from unittest import SkipTest

class TestExpectationFailed(Exception):
    """Raise if a test failed. The constructor should be called with a
    string describing the problem."""
    pass



@contextmanager
def lockfile(file, nolock=False):
    """Context manager for an optional file-based mutex.

    Unless nolock=True the process must hold a lock on the given file
    before entering the context. The lock is released when leaving the
    context.

    """
    if nolock:
        try:
            yield None
        finally:
            pass
    else:
        with open(file, 'w') as lockfile:
            try:
                print(f'Aquiring lock on {file}...', file=sys.stderr)
                fcntl.flock(lockfile, fcntl.LOCK_EX)
                print(f'Got lock on {file}.', file=sys.stderr)
                yield lockfile
            finally:
                print(f'Unlocking {file}...', file=sys.stderr)
                fcntl.flock(lockfile, fcntl.LOCK_UN)
                print(f'Unlocked {file}.', file=sys.stderr)



def first_line_match(regexp, file):
    """Return the first match of the regular expression in file (by line),
    or None. Technically applicable to any iterable containing
    strings, not just files opened for reading.
    """
    for line in file:
        m = regexp.search(line)
        if m:
            return m
    return None



def require_match(regexp, file, error_message=None):
    """Return the first match of the regular expression in file (by line),
    or raise TestExpectationFailed.

    If error_message is not None the exception message will be that
    string, otherwise a generic message containing the regular
    expression pattern. Technically applicable to any iterable
    containing strings, not just files opened for reading.

    """
    m = first_line_match(regexp, file)
    if m:
        return m

    if error_message:
        raise TestExpectationFailed(error_message)
    else:
        raise TestExpectationFailed(f'No match found for {regexp.pattern}!')



def require_apache_modules(*modules):
    """Raise unittest.SkipTest if any of the given module files (full file
    name) is not present in AP_LIBEXECDIR.

    """
    mod_dir = os.environ['AP_LIBEXECDIR']
    for mod in modules:
        if not os.path.isfile(os.path.join(mod_dir, mod)):
            raise SkipTest(f'{mod} not found, skipping.')
