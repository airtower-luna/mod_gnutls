# Copyright 2019 Fiona Klute
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

import errno
import os
import signal
import subprocess
import sys

from contextlib import contextmanager
from pathlib import Path
from time import sleep

class TestService:
    """A generic service used in the mod_gnutls test environment."""

    def __init__(self, start=None, stop=None, env=None,
                 condition=None, check=None, pidfile=None):
        # command to start the service
        self.start_command = start
        # command to stop the service (otherwise use SIGTERM)
        self.stop_command = stop
        # condition: start service if the function returns true
        self.condition = condition or (lambda: True)

        # child process
        self.process = None
        # PID file, if any. The process must delete its PID file when
        # exiting.
        self.pidfile = Path(pidfile) if pidfile else None

        # add environment variables for a subprocess only
        if env:
            self.process_env = os.environ.copy()
            for name, value in env.items():
                self.process_env[name] = value
        else:
            self.process_env = None

        # check: function to check if the service is up and working
        self.check = check

        # sleep step for waiting (sec)
        self._step = int(os.environ.get('TEST_SERVICE_WAIT', 250)) / 1000

    def start(self):
        """Start the service"""
        if not self.condition():
            # skip
            return
        print(f'Starting: {self.start_command}')
        self.process = subprocess.Popen(self.start_command,
                                        env=self.process_env,
                                        close_fds=True)

    def stop(self):
        """Order the service to stop"""
        if not self.condition():
            # skip
            return
        if not self.process or self.process.poll():
            # process either never started or already stopped
            return

        if self.stop_command:
            print(f'Stopping: {self.stop_command}')
            subprocess.run(self.stop_command, check=True, env=self.process_env)
        else:
            print(f'Stopping (SIGTERM): {self.start_command}')
            self.process.terminate()

    def wait(self, timeout=None):
        """Wait for the process to actually stop after calling stop().

        WARNING: Calling this method without a timeout or calling
        stop() first will hang. An expired timeout will raise a
        subprocess.TimeoutExpired exception.

        """
        if self.process:
            self.process.wait(timeout=timeout)
            self.process = None

    def wait_ready(self, timeout=None):
        """Wait for the started service to be ready.

        The function passed to the constructor as "check" is called to
        determine whether it is. Waiting also ends if self.process
        terminates.

        Returns: None if the service is ready, or the return code if
        the process has terminated.

        Raises a TimeoutError if the given timeout has been exceeded.

        """
        if not self.check:
            return None

        slept = 0
        while not timeout or slept < timeout:
            if self.process and self.process.poll():
                return self.process.returncode
            if self.check():
                return None
            else:
                sleep(self._step)
                slept = slept + self._step
        # TODO: A custom ServiceException or something would be nicer
        # here.
        raise TimeoutError('Waiting for service timed out!')

    @contextmanager
    def run(self):
        """Context manager to start and stop a service. Note that entering the
        context does not call TestService.wait_ready() on the service,
        you must do that separately if desired.

        """
        try:
            self.start()
            # TODO: with async execution we could also call
            # wait_ready() here
            yield self
        finally:
            self.stop()
            # TODO: this would really benefit from async execution
            self.wait()



class ApacheService(TestService):
    """An Apache HTTPD instance used in the mod_gnutls test
    environment."""

    apache2 = os.environ.get('APACHE2', 'apache2')

    def __init__(self, config, env=None, pidfile=None, check=None,
                 valgrind_log=None):
        self.config = Path(config).resolve()
        base_cmd = [self.apache2, '-f', str(self.config), '-k']
        start_cmd = base_cmd + ['start', '-DFOREGROUND']
        if valgrind_log:
            start_cmd = ['valgrind', '-s', '--leak-check=full',
                         '--track-origins=yes', '--vgdb=no',
                         f'--log-file={valgrind_log}'] \
                         + start_cmd
        if not check:
            check = self.pidfile_check
        super(ApacheService, self).__init__(start=start_cmd,
                                            stop=base_cmd + ['stop'],
                                            env=env,
                                            pidfile=pidfile,
                                            condition=self.config_exists,
                                            check=check)

    def config_exists(self):
        return self.config.is_file()

    def pidfile_check(self):
        """Default check method for ApacheService, waits for the PID file to
        be present."""
        return self.pidfile.is_file()
