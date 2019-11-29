#!/usr/bin/python3
# PYTHON_ARGCOMPLETE_OK

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

import socket
import subprocess

from http.client import HTTPConnection
from time import sleep

class HTTPSubprocessConnection(HTTPConnection):
    def __init__(self, command, host, port=None,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
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

    def connect(self):
        s_local, s_remote = socket.socketpair(socket.AF_UNIX,
                                              socket.SOCK_STREAM)
        s_local.settimeout(self.timeout)

        # TODO: Maybe capture stderr?
        self._sproc = subprocess.Popen(self.command, stdout=s_remote,
                                       stdin=s_remote, close_fds=True)
        s_remote.close()
        self.sock = s_local

    def close(self):
        super().close()
        # Wait for the process to stop, send SIGTERM/SIGKILL if
        # necessary
        self.returncode = self._sproc.wait(self.timeout)
        if self.returncode == None:
            self._sproc.terminate()
            self.returncode = self._sproc.wait(self.timeout)
            if self.returncode == None:
                self._sproc.kill()
                self.returncode = self._sproc.wait(self.timeout)



def format_response(resp):
    print('{} {}'.format(resp.status, resp.reason))
    for name, value in resp.getheaders():
        print('{}: {}'.format(name, value))
    print()
    print(resp.read().decode())



if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description='Send HTTP requests through gnutls-cli',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('host', nargs='?', help='Access the specified host',
                        default='localhost')
    parser.add_argument('--insecure', action='store_true',
                        help='do not validate the server certificate')
    parser.add_argument('-p', '--port', type=int,
                        help='Access the specified port', default='8000')
    parser.add_argument('--x509cafile', type=str,
                        help='Use the specified CA to validate the '
                        'server certificate')

    # enable bash completion if argcomplete is available
    try:
        import argcomplete
        argcomplete.autocomplete(parser)
    except ImportError:
        pass

    args = parser.parse_args()

    # note: "--logfile" option requires GnuTLS version >= 3.6.7
    command = ['gnutls-cli', '--logfile=/dev/stderr']
    if args.insecure:
        command.append('--insecure')
    if args.x509cafile:
        command.append('--x509cafile')
        command.append(args.x509cafile)
    command = command + ['-p', str(args.port), args.host]

    conn = HTTPSubprocessConnection(command, args.host, port=args.port,
                                    timeout=6.0)
    # Maybe call connect() here to detect handshake errors before
    # sending the request?

    # Add headers={'Host': 'test.host'} to provoke "421 Misdirected
    # Request"
    conn.request('GET', '/')
    resp = conn.getresponse()
    format_response(resp)

    # This could be used to test keepalive behavior
    #sleep(2)

    conn.request('GET', '/test.txt')
    resp = conn.getresponse()
    format_response(resp)

    conn.close()
    exit(conn.returncode)
