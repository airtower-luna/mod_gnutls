#!/usr/bin/python3

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

"""Test objects and support functions for the mod_gnutls test
suite. The classes defined in this module represent structures in the
YAML test configuration files.

"""

import re
import subprocess
import yaml

from . import TestExpectationFailed
from .http import HTTPSubprocessConnection

class TestConnection(yaml.YAMLObject):
    """An HTTP connection in a test. It includes parameters for the
    transport (currently gnutls-cli only), and the actions
    (e.g. sending requests) to take using this connection.

    Note that running one TestConnection object may result in multiple
    sequential network connections, if the transport gets closed in a
    non-failure way (e.g. following a "Connection: close" request) and
    there are more actions, or (rarely) if an action requires its own
    transport.

    """
    yaml_tag = '!connection'

    def __init__(self, actions, gnutls_params=[], transport='gnutls'):
        self.gnutls_params = gnutls_params
        self.actions = actions
        self.transport = transport

    def __repr__(self):
        return (f'{self.__class__.__name__!s}'
                f'(gnutls_params={self.gnutls_params!r}, '
                f'actions={self.actions!r}, transport={self.transport!r})')

    def run(self, host, port, timeout=5.0):
        # note: "--logfile" option requires GnuTLS version >= 3.6.7
        command = ['gnutls-cli', '--logfile=/dev/stderr']
        for s in self.gnutls_params:
            command.append('--' + s)
        command = command + ['-p', str(port), host]

        conn = HTTPSubprocessConnection(command, host, port,
                                        output_filter=filter_cert_log,
                                        timeout=timeout)

        try:
            for act in self.actions:
                if type(act) is TestRequest:
                    act.run(conn)
                elif type(act) is TestRaw10:
                    act.run(command, timeout)
                else:
                    raise TypeError(f'Unsupported action requested: {act!r}')
        finally:
            conn.close()

    @classmethod
    def _from_yaml(cls, loader, node):
        fields = loader.construct_mapping(node)
        conn = TestConnection(**fields)
        return conn



class TestRequest(yaml.YAMLObject):
    """Test action that sends an HTTP/1.1 request.

    The path must be specified in the configuration file, all other
    parameters (method, headers, expected response) have
    defaults.

    Options for checking the response currently are:
    * require a specific response status
    * require the body to exactly match a specific string
    * require the body to contain all of a list of strings

    """
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

    def run(self, conn):
        try:
            conn.request(self.method, self.path, headers=self.headers)
            resp = conn.getresponse()
        except ConnectionResetError as err:
            if self.expects_conn_reset():
                print('connection reset as expected.')
                return
            else:
                raise err
        body = resp.read().decode()
        print(format_response(resp, body))
        self.check_response(resp, body)

    def check_body(self, body):
        """
        >>> r1 = TestRequest(path='/test.txt', method='GET', headers={}, expect={'status': 200, 'body': {'exactly': 'test\\n'}})
        >>> r1.check_body('test\\n')
        >>> r1.check_body('xyz\\n')
        Traceback (most recent call last):
        ...
        mgstest.TestExpectationFailed: Unexpected body: 'xyz\\n' != 'test\\n'
        >>> r2 = TestRequest(path='/test.txt', method='GET', headers={}, expect={'status': 200, 'body': {'contains': ['tes', 'est']}})
        >>> r2.check_body('test\\n')
        >>> r2.check_body('est\\n')
        Traceback (most recent call last):
        ...
        mgstest.TestExpectationFailed: Unexpected body: 'est\\n' does not contain 'tes'
        >>> r3 = TestRequest(path='/test.txt', method='GET', headers={}, expect={'status': 200, 'body': {'contains': 'test'}})
        >>> r3.check_body('test\\n')
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
            self.check_body(body)

    def expects_conn_reset(self):
        """Returns True if running this request is expected to fail due to the
        connection being reset. That usually means the underlying TLS
        connection failed.

        >>> r1 = TestRequest(path='/test.txt', method='GET', headers={}, expect={'status': 200, 'body': {'contains': 'test'}})
        >>> r1.expects_conn_reset()
        False
        >>> r2 = TestRequest(path='/test.txt', method='GET', headers={}, expect={'reset': True})
        >>> r2.expects_conn_reset()
        True
        """
        if 'reset' in self.expect:
            return self.expect['reset']
        return False

    @classmethod
    def _from_yaml(cls, loader, node):
        fields = loader.construct_mapping(node)
        req = TestRequest(**fields)
        return req



class TestRaw10(TestRequest):
    """Test action that sends a request using a minimal (and likely
    incomplete) HTTP/1.0 test client for the one test case that
    strictly requires HTTP/1.0.

    All request parameters (method, path, headers) MUST be specified
    in the config file. Checks on status and body work the same as for
    TestRequest.

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
            self.check_body(body)



# Override the default constructors. Pyyaml ignores default parameters
# otherwise.
yaml.add_constructor('!request', TestRequest._from_yaml, yaml.Loader)
yaml.add_constructor('!connection', TestConnection._from_yaml, yaml.Loader)



def filter_cert_log(in_stream, out_stream):
    """Filter to stop an erroneous gnutls-cli log message.

    This function filters out a log line about loading client
    certificates that is mistakenly sent to stdout from gnutls-cli. My
    fix (https://gitlab.com/gnutls/gnutls/merge_requests/1125) has
    been merged, but buggy binaries will probably be around for a
    while.

    The filter is meant to run in a multiprocessing.Process or
    threading.Thread that receives the stdout of gnutls-cli as
    in_stream, and a connection for further processing as out_stream.

    """
    import fcntl
    import os
    import select
    # message to filter
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
