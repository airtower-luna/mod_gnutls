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

"""Test case hooks for mod_gnutls tests.

Test cases can implement hooks that (depending on the hook) override
or supplement the default test run behavior. Two hooks are currently
supported:

    run_connection:

        Will be called *instead* of mgstests.tests.run_test_conf() and
        is expected to run whatever client actions the test
        requires. This hook receives three parameters:

        * testname: string containing the test name
        * conn_log: file object for connection logging
        * response_log: file object for HTTP response logging

    post_check:

        Execute additional checks if desired. This hook is called
        after the test client run and after the test environment
        terminates. This hook receives two parameters:

        * conn_log: file object with connection log data
        * response_log: file object with HTTP response log data

        With the default client implementation conn_log will contain
        gnutls-cli output, and response_log the full HTTP responses
        (including status line and headers).

"""

import importlib.util
import inspect
import os.path

hooks = [
    'prepare_env',
    'run_connection',
    'post_check'
]

class Plugin:
    """Represents a set of hooks.

    All attribute names listed in the "hooks" field are guaranteed to
    exist in an instance of this class, with the value of each being
    either None or a function.

    """
    def __init__(self, module=None):
        self.module = module
        for hook in hooks:
            if module:
                func = getattr(module, hook, None)
                if func and not inspect.isfunction(func):
                    raise TypeError(f'{hook} in plugin module must be '
                                    'a function!')
                setattr(self, hook, func)
            else:
                setattr(self, hook, None)

def load_module_file(file_path, module_name):
    """Load a module from a file path."""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def load_hooks_plugin(file_path, module_name='mgstest.plugin'):
    """Load a hooks plugin module from the given path, if it
    exists. Returns a Plugin instance without any hooks if the module
    file does not exist.
    """
    if os.path.exists(file_path):
        return Plugin(module=load_module_file(file_path, module_name))
    else:
        return Plugin()
