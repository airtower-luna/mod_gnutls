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

"""HTTP handling components for mod_gnutls tests."""

import contextlib
import socket
import subprocess
import sys

from http.client import HTTPConnection
from threading import Thread

class HTTPSubprocessConnection(HTTPConnection):
    """An HTTPConnection that transports data through a subprocess instead
    of a socket. The mod_gnutls test suite uses it to transport data
    through gnutls-cli instead of the ssl module.

    """
    def __init__(self, command, host, port=None,
                 output_filter=None,
                 stderr_log=None,
                 timeout=socket.getdefaulttimeout(),
                 blocksize=8192):
        super(HTTPSubprocessConnection, self).__init__(host, port, timeout,
                                                       source_address=None,
                                                       blocksize=blocksize)
        # "command" must be a list containing binary and command line
        # parameters
        self.command = command
        # This will be the subprocess reference when connected
        self._sproc = None
        # The subprocess return code is stored here on close()
        self.returncode = None
        # The set_tunnel method of the super class is not supported
        # (see exception doc)
        self.set_tunnel = None
        # This method will be run in a separate process and filter the
        # stdout of self._sproc. Its arguments are self._sproc.stdout
        # and the socket back to the HTTP connection (write-only).
        self._output_filter = output_filter
        # If not None, write a copy of the subprocess' stderr to here.
        self._stderr_log = stderr_log
        # output filter thread
        self._fthread = None
        # Error stream handler thread. This is needed to synchronize
        # output between Python and the subprocess.
        self._ethread = None

    def connect(self):
        s_local, s_remote = socket.socketpair(socket.AF_UNIX,
                                              socket.SOCK_STREAM)
        s_local.settimeout(self.timeout)

        if self._output_filter:
            self._sproc = subprocess.Popen(self.command, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE,
                                           stdin=s_remote, close_fds=True,
                                           bufsize=0)
            self._fthread = Thread(target=self._output_filter,
                                   args=(self._sproc.stdout, s_remote))
            self._fthread.start()
        else:
            self._sproc = subprocess.Popen(self.command, stdout=s_remote,
                                           stderr=subprocess.PIPE,
                                           stdin=s_remote, close_fds=True,
                                           bufsize=0)
        self._ethread = Thread(target=_stderr_writer,
                               args=(self._sproc.stderr, self._stderr_log))
        self._ethread.start()
        self.sock = s_local

    def close(self):
        # close socket to subprocess for writing
        if self.sock:
            self.sock.shutdown(socket.SHUT_WR)

        # Wait for the process to stop, send SIGTERM/SIGKILL if
        # necessary
        if self._sproc:
            try:
                self.returncode = self._sproc.wait(self.timeout)
            except subprocess.TimeoutExpired:
                try:
                    self._sproc.terminate()
                    self.returncode = self._sproc.wait(self.timeout)
                except subprocess.TimeoutExpired:
                    self._sproc.kill()
                    self.returncode = self._sproc.wait(self.timeout)

        # filter thread receives HUP on pipe when the subprocess
        # terminates
        if self._fthread:
            self._fthread.join()
        if self._ethread:
            self._ethread.join()

        # close the connection in the super class, which also calls
        # self.sock.close()
        super().close()



def _stderr_writer(stream, copy=None):
    """Flush incoming data to sys.stderr, and optionally to "copy".

    This is a workaround to prevent output from gnutls-cli and the
    Python interpreter overwriting each other in the test
    logs. Forcing gnutls-cli stderr through Python ensures
    synchronization (via global interpreter lock).

    The incoming stream is closed after all lines have been read.

    """
    with contextlib.closing(stream):
        for line in stream:
            print(line.decode(), file=sys.stderr, end='', flush=True)
            if copy:
                print(line.decode(), file=copy, end='')
