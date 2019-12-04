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

import re
import socket
import subprocess
import yaml

from http.client import HTTPConnection
from multiprocessing import Process
from time import sleep

class HTTPSubprocessConnection(HTTPConnection):
    def __init__(self, command, host, port=None,
                 output_filter=None,
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
        # This method will be run in a separate process and filter the
        # stdout of self._sproc. Its arguments are self._sproc.stdout
        # and the socket back to the HTTP connection (write-only).
        self._output_filter = output_filter
        # output filter process
        self._fproc = None

    def connect(self):
        s_local, s_remote = socket.socketpair(socket.AF_UNIX,
                                              socket.SOCK_STREAM)
        s_local.settimeout(self.timeout)

        # TODO: Maybe capture stderr?
        if self._output_filter:
            self._sproc = subprocess.Popen(self.command, stdout=subprocess.PIPE,
                                           stdin=s_remote, close_fds=True,
                                           bufsize=0)
            self._fproc = Process(target=self._output_filter,
                                  args=(self._sproc.stdout, s_remote))
            self._fproc.start()
        else:
            self._sproc = subprocess.Popen(self.command, stdout=s_remote,
                                           stdin=s_remote, close_fds=True,
                                           bufsize=0)
        s_remote.close()
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

        # filter process receives HUP on pipe when the subprocess
        # terminates
        if self._fproc:
            self._fproc.join()

        # close the connection in the super class, which also calls
        # self.sock.close()
        super().close()



class TestRequest(yaml.YAMLObject):
    yaml_tag = '!request'
    def __init__(self, path, method='GET', headers=dict(),
                 expect=dict(status=200)):
        self.method = method
        self.path = path
        self.headers = headers
        self.expect = expect

    def __repr__(self):
        return (f'{self.__class__.__name__!s}(path={self.path!r}, '
                f'method={self.method!r}, headers={self.headers!r}, '
                f'expect={self.expect!r})')

    def _check_body(self, body):
        """
        >>> r1 = TestRequest(path='/test.txt', method='GET', headers={}, expect={'status': 200, 'body': {'exactly': 'test\\n'}})
        >>> r1._check_body('test\\n')
        >>> r1._check_body('xyz\\n')
        Traceback (most recent call last):
        ...
        https-test-client.TestExpectationFailed: Unexpected body: 'xyz\\n' != 'test\\n'
        >>> r2 = TestRequest(path='/test.txt', method='GET', headers={}, expect={'status': 200, 'body': {'contains': ['tes', 'est']}})
        >>> r2._check_body('test\\n')
        >>> r2._check_body('est\\n')
        Traceback (most recent call last):
        ...
        https-test-client.TestExpectationFailed: Unexpected body: 'est\\n' does not contain 'tes'
        >>> r3 = TestRequest(path='/test.txt', method='GET', headers={}, expect={'status': 200, 'body': {'contains': 'test'}})
        >>> r3._check_body('test\\n')
        """
        if 'exactly' in self.expect['body'] \
           and body != self.expect['body']['exactly']:
            raise TestExpectationFailed(
                f'Unexpected body: {body!r} != '
                f'{self.expect["body"]["exactly"]!r}')
        if 'contains' in self.expect['body']:
            if type(self.expect['body']['contains']) is str:
                self.expect['body']['contains'] = [
                    self.expect['body']['contains']]
            for s in self.expect['body']['contains']:
                if not s in body:
                    raise TestExpectationFailed(
                        f'Unexpected body: {body!r} does not contain '
                        f'{s!r}')

    def check_response(self, response, body):
        if self.expects_conn_reset():
            raise TestExpectationFailed(
                'Got a response, but connection should have failed!')
        if response.status != self.expect['status']:
            raise TestExpectationFailed(
                f'Unexpected status: {response.status} != '
                f'{self.expect["status"]}')
        if 'body' in self.expect:
            self._check_body(body)

    def expects_conn_reset(self):
        if 'reset' in self.expect:
            return self.expect['reset']
        return False

    @classmethod
    def _from_yaml(cls, loader, node):
        fields = loader.construct_mapping(node)
        req = TestRequest(**fields)
        return req

class TestConnection(yaml.YAMLObject):
    yaml_tag = '!connection'

    def __init__(self, actions, gnutls_params=[], transport='gnutls'):
        self.gnutls_params = gnutls_params
        self.actions = actions
        self.transport = transport

    def __repr__(self):
        return (f'{self.__class__.__name__!s}'
                f'(gnutls_params={self.gnutls_params!r}, '
                f'actions={self.actions!r}, transport={self.transport!r})')

    @classmethod
    def _from_yaml(cls, loader, node):
        fields = loader.construct_mapping(node)
        conn = TestConnection(**fields)
        return conn

class TestRaw10(TestRequest):
    """This is a minimal (and likely incomplete) HTTP/1.0 test client for
    the one test case that strictly requires HTTP/1.0. All request
    parameters (method, path, headers) MUST be specified in the config
    file.

    """
    yaml_tag = '!raw10'
    status_re = re.compile('^HTTP/([\d\.]+) (\d+) (.*)$')

    def __init__(self, method, path, headers, expect):
        self.method = method
        self.path = path
        self.headers = headers
        self.expect = expect

    def __repr__(self):
        return (f'{self.__class__.__name__!s}'
                f'(method={self.method!r}, path={self.path!r}, '
                f'headers={self.headers!r}, expect={self.expect!r})')

    def run(self, command, timeout=None):
        req = f'{self.method} {self.path} HTTP/1.0\r\n'
        for name, value in self.headers.items():
            req = req + f'{name}: {value}\r\n'
        req = req + f'\r\n'
        proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                                stdin=subprocess.PIPE, close_fds=True,
                                bufsize=0)
        try:
            # Note: errs will be empty because stderr is not captured
            outs, errs = proc.communicate(input=req.encode(),
                                          timeout=timeout)
        except TimeoutExpired:
            proc.kill()
            outs, errs = proc.communicate()

        # first line of the received data must be the status
        status, rest = outs.decode().split('\r\n', maxsplit=1)
        # headers and body are separated by double newline
        headers, body = rest.split('\r\n\r\n', maxsplit=1)
        # log response for debugging
        print(f'{status}\n{headers}\n\n{body}')

        m = self.status_re.match(status)
        if m:
            status_code = int(m.group(2))
            status_expect = self.expect.get('status')
            if status_expect and not status_code == status_expect:
                raise TestExpectationFailed('Unexpected status code: '
                                            f'{status}, expected '
                                            f'{status_expect}')
        else:
            raise TestExpectationFailed(f'Invalid status line: "{status}"')

        if 'body' in self.expect:
            self._check_body(body)

# Override the default constructors. Pyyaml ignores default parameters
# otherwise.
yaml.add_constructor('!request', TestRequest._from_yaml, yaml.Loader)
yaml.add_constructor('!connection', TestConnection._from_yaml, yaml.Loader)



class TestExpectationFailed(Exception):
    """Raise if a test failed. The constructor should be called with a
    string describing the problem."""
    pass



def filter_cert_log(in_stream, out_stream):
    import fcntl
    import os
    import select
    # This filters out a log line about loading client
    # certificates that is mistakenly sent to stdout. My fix has
    # been merged, but buggy binaries will probably be around for
    # a while.
    # https://gitlab.com/gnutls/gnutls/merge_requests/1125
    cert_log = b'Processed 1 client X.509 certificates...\n'

    # Set the input to non-blocking mode
    fd = in_stream.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    # The poll object allows waiting for events on non-blocking IO
    # channels.
    poller = select.poll()
    poller.register(fd)

    init_done = False
    run_loop = True
    while run_loop:
        # The returned tuples are file descriptor and event, but
        # we're only listening on one stream anyway, so we don't
        # need to check it here.
        for x, event in poller.poll():
            # Critical: "event" is a bitwise OR of the POLL* constants
            if event & select.POLLIN or event & select.POLLPRI:
                data = in_stream.read()
                if not init_done:
                    # If the erroneous log line shows up it's the
                    # first piece of data we receive. Just copy
                    # everything after.
                    init_done = True
                    if cert_log in data:
                        data = data.replace(cert_log, b'')
                out_stream.send(data)
            if event & select.POLLHUP or event & select.POLLRDHUP:
                # Stop the loop, but process any other events that
                # might be in the list returned by poll() first.
                run_loop = False

    in_stream.close()
    out_stream.close()



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
                                    output_filter=filter_cert_log,
                                    timeout=6.0)

    try:
        for act in test_actions:
            if type(act) is TestRequest:
                try:
                    conn.request(act.method, act.path, headers=act.headers)
                    resp = conn.getresponse()
                except ConnectionResetError as err:
                    if act.expects_conn_reset():
                        print('connection reset as expected.')
                        break
                    else:
                        raise err
                body = resp.read().decode()
                print(format_response(resp, body))
                act.check_response(resp, body)
            elif type(act) is TestRaw10:
                act.run(command, conn.timeout)
            else:
                raise TypeError(f'Unsupported action requested: {act!r}')
    finally:
        conn.close()
