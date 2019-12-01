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
import yaml

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



class TestRequest(yaml.YAMLObject):
    yaml_tag = '!request'
    def __init__(self, path, expect=dict(status=200), method='GET'):
        self.method = method
        self.path = path
        self.expect = expect

    def __repr__(self):
        return (f'{self.__class__.__name__!s}(path={self.path!r}, '
                f'expect={self.expect!r}, method={self.method!r})')

    def check_response(self, response, body):
        if response.status != self.expect['status']:
            raise TestExpectationFailed(
                f'Unexpected status: {response.status} != '
                f'{self.expect["status"]}')
        if 'body' in self.expect and self.expect['body'] != body:
            raise TestExpectationFailed(
                f'Unexpected body: {body!r} != {self.expect["body"]!r}')

    @classmethod
    def _from_yaml(cls, loader, node):
        fields = loader.construct_mapping(node)
        req = TestRequest(**fields)
        return req

class TestConnection(yaml.YAMLObject):
    yaml_tag = '!connection'

    def __init__(self, actions, gnutls_params=[], protocol='https'):
        self.gnutls_params = gnutls_params
        self.actions = actions
        self.protocol = protocol

    def __repr__(self):
        return (f'{self.__class__.__name__!s}'
                f'(gnutls_params={self.gnutls_params!r}, '
                f'actions={self.actions!r}, protocol={self.protocol!r})')

    @classmethod
    def _from_yaml(cls, loader, node):
        fields = loader.construct_mapping(node)
        conn = TestConnection(**fields)
        return conn

# Override the default constructors. Pyyaml ignores default parameters
# otherwise.
yaml.add_constructor('!request', TestRequest._from_yaml, yaml.Loader)
yaml.add_constructor('!connection', TestConnection._from_yaml, yaml.Loader)



class TestExpectationFailed(Exception):
    """Raise if a test failed. The constructor should be called with a
    string describing the problem."""
    pass



def format_response(resp, body):
    s = f'{resp.status} {resp.reason}\n'
    s = s + '\n'.join(f'{name}: {value}' for name, value in resp.getheaders())
    s = s + '\n\n' + body
    return s



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
    parser.add_argument('--test-config', type=argparse.FileType('r'),
                        help='load YAML test configuration')

    # enable bash completion if argcomplete is available
    try:
        import argcomplete
        argcomplete.autocomplete(parser)
    except ImportError:
        pass

    args = parser.parse_args()

    test_conn = None
    test_actions = None

    if args.test_config:
        config = yaml.load(args.test_config, Loader=yaml.Loader)
        if type(config) is TestConnection:
            test_conn = config
            print(test_conn)
            test_actions = test_conn.actions
    else:
        # simple default request
        test_actions = [TestRequest(path='/test.txt',
                                    expect={'status': 200, 'body': 'test\n'},
                                    method='GET')]


    # note: "--logfile" option requires GnuTLS version >= 3.6.7
    command = ['gnutls-cli', '--logfile=/dev/stderr']
    if args.insecure:
        command.append('--insecure')
    if args.x509cafile:
        command.append('--x509cafile')
        command.append(args.x509cafile)
    if test_conn != None:
        for s in test_conn.gnutls_params:
            command.append('--' + s)
    command = command + ['-p', str(args.port), args.host]

    conn = HTTPSubprocessConnection(command, args.host, port=args.port,
                                    timeout=6.0)

    try:
        for act in test_actions:
            if type(act) is TestRequest:
                # Add headers={'Host': 'test.host'} to provoke "421
                # Misdirected
                conn.request(act.method, act.path)
                resp = conn.getresponse()
                body = resp.read().decode()
                print(format_response(resp, body))
                act.check_response(resp, body)
            else:
                raise TypeError(f'Unsupported action requested: {act!r}')
    finally:
        conn.close()
