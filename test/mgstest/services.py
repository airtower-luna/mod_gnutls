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

"""Handling services needed for mod_gnutls tests"""

import asyncio
import os

from contextlib import asynccontextmanager
from pathlib import Path


class TestService:
    """A generic service used in the mod_gnutls test environment."""

    def __init__(self, start=None, stop=None, env=None,
                 condition=None, check=None):
        # command to start the service
        self.start_command = start
        # command to stop the service (otherwise use SIGTERM)
        self.stop_command = stop
        # condition: start service if the function returns true
        self.condition = condition or (lambda: True)

        # child process
        self.process = None
        # will contain the return code of the child process after
        # successful wait()
        self.returncode = None

        # add environment variables for a subprocess only
        if env:
            self.process_env = os.environ.copy()
            for name, value in env.items():
                self.process_env[name] = value
        else:
            self.process_env = None

        # check: coroutine to check if the service is up and working
        self.check = check

        # sleep step for waiting (sec)
        self._step = int(os.environ.get('TEST_SERVICE_WAIT', 250)) / 1000

    async def start(self):
        """Start the service"""
        if not self.condition():
            # skip
            return
        print(f'Starting: {self.start_command}')
        self.process = await asyncio.create_subprocess_exec(
            *self.start_command, env=self.process_env, close_fds=True)
        self.returncode = None

    async def stop(self):
        """Order the service to stop"""
        if not self.condition():
            # skip
            return
        if not self.process or self.process.returncode is not None:
            # process either never started or already stopped
            return

        if self.stop_command:
            print(f'Stopping: {self.stop_command}')
            stop = await asyncio.create_subprocess_exec(
                *self.stop_command, env=self.process_env)
            await stop.wait()
        else:
            print(f'Stopping (SIGTERM): {self.start_command}')
            self.process.terminate()

    async def wait(self):
        """Wait for the process to terminate.

        Sets returncode to the process' return code and returns it.

        WARNING: Calling this method without calling stop() first will
        hang, unless the service stops on its own. Wrap in
        asyncio.wait_for() as needed.

        """
        if self.process:
            await self.process.wait()
            self.returncode = self.process.returncode
            self.process = None
            return self.returncode

    async def wait_ready(self):
        """Wait for the started service to be ready.

        The function passed to the constructor as "check" is called to
        determine whether it is. Waiting also ends if self.process
        terminates.

        Returns: None if the service is ready, or the return code if
        the process has terminated.

        """
        if not self.condition():
            # skip
            return None
        if not self.check:
            return None

        while True:
            if self.process and self.process.returncode is not None:
                return self.process.returncode
            if await self.check():
                return None
            else:
                await asyncio.sleep(self._step)

    @asynccontextmanager
    async def run(self, ready_timeout=None):
        """Context manager to start and stop a service. Yields when the
        service is ready.

        """
        try:
            await self.start()
            await asyncio.wait_for(self.wait_ready(), timeout=ready_timeout)
            yield self
        finally:
            await self.stop()
            await self.wait()


class ApacheService(TestService):
    """An Apache HTTPD instance used in the mod_gnutls test
    environment."""

    apache2 = os.environ.get('APACHE2', 'apache2')

    def __init__(self, config, pidfile, env=None, check=None,
                 valgrind_log=None, valgrind_suppress=[]):
        self.config = Path(config).resolve()
        # PID file, used by default to check if the server is up.
        self.pidfile = Path(pidfile)
        base_cmd = [self.apache2, '-f', str(self.config), '-k']
        start_cmd = base_cmd + ['start', '-DFOREGROUND']
        if valgrind_log:
            valgrind = os.environ.get('VALGRIND', 'valgrind')
            suppress = [f'--suppressions={s}' for s in valgrind_suppress]
            start_cmd = [valgrind, '-v', '--leak-check=full',
                         '--num-callers=20',
                         '--gen-suppressions=all',
                         '--keep-debuginfo=yes',
                         '--track-origins=yes', '--vgdb=no',
                         f'--log-file={valgrind_log}'] \
                + suppress + start_cmd
        if not check:
            check = self.pidfile_check
        super(ApacheService, self).__init__(start=start_cmd,
                                            stop=base_cmd + ['stop'],
                                            env=env,
                                            condition=self.config_exists,
                                            check=check)

    def config_exists(self):
        return self.config.is_file()

    async def pidfile_check(self):
        """Default check method for ApacheService, waits for the PID file to
        be present."""
        return self.pidfile.is_file()
