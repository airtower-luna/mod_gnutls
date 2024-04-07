# Copyright 2019-2024 Fiona Klute
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

The test configuration file defines either a TestConnection, or a list
of them. Each connection contains a list of actions to run using this
connection. The actions define their expected results, if an
expectation is not met mgstest.TestExpectationFailed is raised.

Example of a connection that runs two request actions, which are
expected to succeed:

```yaml
!connection
# "host" defaults to $TEST_TARGET, so usually there's no need to set
# it. You can use ${VAR} to substitute environment variables.
host: 'localhost'
# "port" defaults to $TEST_PORT, so usually there's no need to set it
# it. You can use ${VAR} to substitute environment variables.
port: '${TEST_PORT}'
# All elements of gnutls_params will be prefixed with "--" and passed
# to gnutls-cli on the command line.
gnutls_params:
  - x509cafile=authority/x509.pem
# The transport encryption. "Gnutls" is the default, "plain" can be
# set to get an unencrypted connection (e.g. to test redirection to
# HTTPS).
transport: 'gnutls'
description: 'This connection description will be logged.'
actions:
  - !request
    # GET is the default.
    method: GET
    # The path part of the URL, required.
    path: /test.txt
    # "Expect" defines how the response must look to pass the test.
    expect:
      # 200 (OK) is the default.
      status: 200
      # The response body is analyzed only if the "body" element
      # exists, otherwise any content is accepted.
      body:
        # The full response body must exactly match this string.
        exactly: |
          test
  - !request
    path: /status?auto
    expect:
      # The headers are analyzed only if the "headers" element exists.
      headers:
        # The Content-Type header must be present with exactly this
        # value. You can use ${VAR} to substitute environment
        # variables in the value.
        Content-Type: 'text/plain; charset=ISO-8859-1'
        # You can check the absence of a header by expecting null:
        X-Forbidden-Header: null
      body:
        # All strings in this list must occur in the body, in any
        # order. "Contains" may also contain a single string instead
        # of a list.
        contains:
          - 'Using GnuTLS version: '
          - 'Current TLS session: (TLS1.3)'
```

Example of a connection that is expected to fail at the TLS level, in
this case because the configured CA is not the one that issued the
server certificate:

```yaml
- !connection
  gnutls_params:
    - x509cafile=rogueca/x509.pem
  actions:
    - !request
      path: /
      expect:
        # The connection is expected to reset without an HTTP response.
        reset: yes
```

"""

import os
import re
import select
import subprocess
import sys
import yaml

from enum import Enum, auto
from http.client import HTTPConnection
from string import Template

from . import TestExpectationFailed
from .http import HTTPSubprocessConnection


class Transports(Enum):
    """Transports supported by TestConnection."""
    GNUTLS = auto()
    PLAIN = auto()

    def __repr__(self):
        return f'{self.__class__.__name__!s}.{self.name}'


class TestConnection(yaml.YAMLObject):
    """An HTTP connection in a test. It includes parameters for the
    transport, and the actions (e.g. sending requests) to take using
    this connection.

    Note that running one TestConnection object may result in multiple
    sequential network connections if the transport gets closed in a
    non-failure way (e.g. following a "Connection: close" request) and
    there are more actions, or (rarely) if an action requires its own
    transport.

    """
    yaml_tag = '!connection'

    def __init__(self, actions, host=None, port=None, gnutls_params=[],
                 transport='gnutls', description=None):
        self.gnutls_params = gnutls_params
        self.actions = actions
        self.transport = Transports[transport.upper()]
        self.description = description
        self.host = host
        self.port = port

    def __repr__(self):
        return (f'{self.__class__.__name__!s}'
                f'(host={self.host!r}, port={self.port!r}, '
                f'gnutls_params={self.gnutls_params!r}, '
                f'actions={self.actions!r}, transport={self.transport!r}, '
                f'description={self.description!r})')

    def run(self, timeout=5.0, conn_log=None, response_log=None):
        """Set up an HTTP connection and run the configured actions."""

        if self.host:
            self.host = subst_env(self.host)
        else:
            self.host = os.environ.get('TEST_TARGET', 'localhost')
        if self.port:
            self.port = int(subst_env(self.port))
        else:
            self.port = int(os.environ.get('TEST_PORT', 8000))

        # note: "--logfile" option requires GnuTLS version >= 3.6.7
        command = ['gnutls-cli', '--logfile=/dev/stderr']
        for s in self.gnutls_params:
            command.append('--' + s)
        command = command + ['-p', str(self.port), self.host]

        if self.transport == Transports.GNUTLS:
            conn = HTTPSubprocessConnection(command, self.host, self.port,
                                            cwd=os.environ['builddir'],
                                            output_filter=filter_cert_log,
                                            stderr_log=conn_log,
                                            timeout=timeout)
        elif self.transport == Transports.PLAIN:
            conn = HTTPConnection(self.host, port=self.port,
                                  timeout=timeout)

        try:
            for act in self.actions:
                if type(act) is TestRequest:
                    act.run(conn, response_log)
                elif type(act) is TestReq10:
                    act.run(command, timeout, conn_log, response_log)
                elif type(act) is Resume:
                    act.run(conn, command)
                else:
                    raise TypeError(f'Unsupported action requested: {act!r}')
        finally:
            conn.close()
            sys.stdout.flush()

    @classmethod
    def from_yaml(cls, loader, node):
        fields = loader.construct_mapping(node)
        conn = cls(**fields)
        return conn


class TestRequest(yaml.YAMLObject):
    """Test action that sends an HTTP/1.1 request.

    The path must be specified in the configuration file, all other
    parameters (method, headers, expected response) have
    defaults.

    Options for checking the response currently are:
    * require a specific response status
    * require specific headers to be present with specific values
    * require the body to exactly match a specific string
    * require the body to contain all of a list of strings

    """
    yaml_tag = '!request'

    def __init__(self, path, method='GET', body=None, headers=dict(),
                 expect=dict(status=200)):
        self.method = method
        self.path = path
        self.body = body.encode('utf-8') if body else None
        self.headers = headers
        self.expect = expect

    def __repr__(self):
        return (f'{self.__class__.__name__!s}(path={self.path!r}, '
                f'method={self.method!r}, body={self.body!r}, '
                f'headers={self.headers!r}, expect={self.expect!r})')

    def run(self, conn, response_log=None):
        try:
            conn.request(self.method, self.path, body=self.body,
                         headers=self.headers)
            resp = conn.getresponse()
            if self.expects_conn_reset():
                raise TestExpectationFailed(
                    'Expected connection reset did not occur!')
        except (BrokenPipeError, ConnectionResetError) as err:
            if self.expects_conn_reset():
                print('connection reset as expected.')
                return
            else:
                raise err
        body = resp.read().decode()
        log_str = format_response(resp, body)
        print(log_str)
        if response_log:
            print(log_str, file=response_log)
        self.check_response(resp, body)

    def check_headers(self, headers):
        for name, expected in self.expect['headers'].items():
            value = headers.get(name)
            expected = subst_env(expected)
            if value != expected:
                raise TestExpectationFailed(
                    f'Unexpected value in header {name}: {value!r}, '
                    f'expected {expected!r}')

    def check_body(self, body):
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
                if s not in body:
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
        if 'headers' in self.expect:
            self.check_headers(dict(response.getheaders()))
        if 'body' in self.expect:
            self.check_body(body)

    def expects_conn_reset(self):
        """Returns True if running this request is expected to fail due to the
        connection being reset. That usually means the underlying TLS
        connection failed.
        """
        if 'reset' in self.expect:
            return self.expect['reset']
        return False

    @classmethod
    def from_yaml(cls, loader, node):
        fields = loader.construct_mapping(node)
        req = cls(**fields)
        return req


class TestReq10(TestRequest):
    """Test action that sends a request using a minimal (and likely
    incomplete) HTTP/1.0 test client for the one test case that
    strictly requires HTTP/1.0.

    TestReq10 objects use the same YAML parameters and defaults as
    TestRequest, but note that an empty "headers" parameter means that
    not even a "Host:" header will be sent. All headers must be
    specified in the test configuration file.

    """
    yaml_tag = '!request10'
    status_re = re.compile(r'^HTTP/([\d\.]+) (\d+) (.*)$')
    header_re = re.compile(r'^([-\w]+):\s+(.*)$')

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def run(self, command, timeout=None, conn_log=None, response_log=None):
        req = f'{self.method} {self.path} HTTP/1.0\r\n'
        for name, value in self.headers.items():
            req = req + f'{name}: {value}\r\n'
        req = req.encode('utf-8') + b'\r\n'
        if self.body:
            req = req + self.body
        proc = subprocess.Popen(command,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                stdin=subprocess.PIPE,
                                close_fds=True,
                                bufsize=0)
        try:
            outs, errs = proc.communicate(input=req, timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            outs, errs = proc.communicate()

        print(errs.decode())
        if conn_log:
            print(errs.decode(), file=conn_log)

        if proc.returncode != 0:
            if len(outs) != 0:
                raise TestExpectationFailed(
                    f'Connection failed, but got output: {outs!r}')
            if self.expects_conn_reset():
                print('connection reset as expected.')
                return
            else:
                raise TestExpectationFailed(
                    'Connection failed unexpectedly!')
        else:
            if self.expects_conn_reset():
                raise TestExpectationFailed(
                    'Expected connection reset did not occur!')

        # first line of the received data must be the status
        status, rest = outs.decode().split('\r\n', maxsplit=1)
        # headers and body are separated by double newline
        head, body = rest.split('\r\n\r\n', maxsplit=1)
        # log response for debugging
        print(f'{status}\n{head}\n\n{body}')
        if response_log:
            print(f'{status}\n{head}\n\n{body}', file=response_log)

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

        if 'headers' in self.expect:
            headers = dict()
            for line in head.splitlines():
                m = self.header_re.fullmatch(line)
                if m:
                    headers[m.group(1)] = m.group(2)
            self.check_headers(headers)

        if 'body' in self.expect:
            self.check_body(body)


class Resume(yaml.YAMLObject):
    """Test action to close and resume the TLS session.

    Send the gnutls-cli inline command "^resume^" to close and resume
    the TLS session. "inline-commands" must be present in
    gnutls_params of the parent connection. This action does not need
    any arguments, but you must specify with an explicitly empty
    dictionary for YAML parsing to work, like this:

      !resume {}

    """
    yaml_tag = '!resume'

    def run(self, conn, command):
        if '--inline-commands' not in command:
            raise ValueError('gnutls_params must include "inline-commands" '
                             'to use the resume action!')
        if not type(conn) is HTTPSubprocessConnection:
            raise TypeError('Resume action works only with '
                            'HTTPSubprocessConnection.')
        conn.sock.send(b'^resume^\n')


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
    # message to filter
    cert_log = b'Processed 1 client X.509 certificates...\n'

    # Set the input to non-blocking mode
    fd = in_stream.fileno()
    os.set_blocking(fd, False)

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
    """Format an http.client.HTTPResponse for logging."""
    s = f'{resp.status} {resp.reason}\n'
    s = s + '\n'.join(f'{name}: {value}' for name, value in resp.getheaders())
    s = s + '\n\n' + body
    return s


def subst_env(text):
    """Use the parameter "text" as a template, substitute with environment
    variables.

    >>> os.environ['EXAMPLE_VAR'] = 'abc'
    >>> subst_env('${EXAMPLE_VAR}def')
    'abcdef'

    Referencing undefined environment variables causes a KeyError.

    >>> subst_env('${EXAMPLE_UNSET}')
    Traceback (most recent call last):
    ...
    KeyError: 'EXAMPLE_UNSET'

    >>> subst_env(None) is None
    True

    """
    if not text:
        return None
    t = Template(text)
    return t.substitute(os.environ)


def run_test_conf(test_config, timeout=5.0, conn_log=None, response_log=None):
    """Load and run a test configuration.

    The test_conf parameter must either a single TestConnection
    object, or a list of such objects to be run in order. The other
    three parameters are forwarded to TestConnection.run().

    """
    conns = None

    if type(test_config) is TestConnection:
        conns = [test_config]
    elif type(test_config) is list:
        # assume list elements are connections
        conns = test_config
    else:
        raise TypeError(f'Unsupported configuration: {test_config!r}')
    sys.stdout.flush()

    for i, test_conn in enumerate(conns):
        if test_conn.description:
            print(f'Running test connection {i}: {test_conn.description}')
        else:
            print(f'Running test connection {i}.')
        sys.stdout.flush()
        test_conn.run(timeout=timeout, conn_log=conn_log,
                      response_log=response_log)
