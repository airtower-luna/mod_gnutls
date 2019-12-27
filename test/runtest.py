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

import contextlib
import os
import os.path
import subprocess
import sys

import mgstest.hooks
from mgstest import lockfile, TestExpectationFailed
from mgstest.services import ApacheService, TestService
from mgstest.tests import run_test_conf



def find_testdir(number, dir):
    """Find the configuration directory for a test based on its
    number. The given directory must contain exactly one directory
    with a name matching "NUMBER_*", otherwise a LookupError is
    raised.

    """
    with os.scandir(dir) as it:
        found = None
        for entry in it:
            if entry.is_dir():
                num = int(entry.name.split('_', maxsplit=1)[0])
                if number == num:
                    if found:
                        # duplicate numbers are an error
                        raise LookupError('Multiple directories found for '
                                          f'test number {args.test_number}: '
                                          f'{found.name} and {entry.name}')
                    else:
                        found = entry
        if found == None:
            raise LookupError('No test directory found for test number '
                              f'{args.test_number}!')
        else:
            return (found.path, found.name)



def check_ocsp_responder():
    # Check if OCSP responder works
    issuer_cert = 'authority/x509.pem'
    check_cert = 'authority/server/x509.pem'
    command = ['ocsptool', '--ask', '--nonce',
               '--load-issuer', issuer_cert,
               '--load-cert', check_cert]
    return subprocess.run(command).returncode == 0

def check_msva():
    # Check if MSVA is up
    cert_file = 'authority/client/x509.pem'
    uid_file = 'authority/client/uid'
    with open(uid_file, 'r') as file:
        uid = file.read().strip()
        command = ['msva-query-agent', 'https', uid, 'x509pem', 'client']
        with open(cert_file, 'r') as cert:
            return subprocess.run(command, stdin=cert).returncode == 0



if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description='Run a mod_gnutls server test')
    parser.add_argument('--test-number', type=int,
                        required=True, help='load YAML test configuration')
    parser.add_argument('--log-connection', type=str, default=None,
                        help='write connection log to this file')
    parser.add_argument('--log-responses', type=str, default=None,
                        help='write HTTP responses to this file')

    # enable bash completion if argcomplete is available
    try:
        import argcomplete
        argcomplete.autocomplete(parser)
    except ImportError:
        pass

    args = parser.parse_args()

    # The Automake environment always provides srcdir, the default is
    # for manual use.
    srcdir = os.path.realpath(os.environ.get('srcdir', '.'))
    # ensure environment srcdir is absolute
    os.environ['srcdir'] = srcdir

    # Find the configuration directory for the test in
    # ${srcdir}/tests/, based on the test number.
    testdir, testname = find_testdir(args.test_number,
                                     os.path.join(srcdir, 'tests'))
    print(f'Found test {testname}, test dir is {testdir}')
    os.environ['TEST_NAME'] = testname

    # Load test case hooks (if any)
    plugin_path = os.path.join(testdir, 'hooks.py')
    plugin = mgstest.hooks.load_hooks_plugin(plugin_path)

    # PID file name varies depending on whether we're using
    # namespaces.
    #
    # TODO: Check if having the different names is really necessary.
    pidaffix = ''
    if 'USE_TEST_NAMESPACE' in os.environ:
        pidaffix = f'-{testname}'

    # Define the available services
    apache = ApacheService(config=os.path.join(testdir, 'apache.conf'),
                           pidfile=f'apache2{pidaffix}.pid')
    backend = ApacheService(config=os.path.join(testdir, 'backend.conf'),
                            pidfile=f'backend{pidaffix}.pid')
    ocsp = ApacheService(config=os.path.join(testdir, 'ocsp.conf'),
                         pidfile=f'ocsp{pidaffix}.pid',
                         check=check_ocsp_responder)
    msva = TestService(start=['monkeysphere-validation-agent'],
                       env={'GNUPGHOME': 'msva.gnupghome',
                            'MSVA_KEYSERVER_POLICY': 'never'},
                       condition=lambda: 'USE_MSVA' in os.environ,
                       check=check_msva)

    # background services: must be ready before the main apache
    # instance is started
    bg_services = [backend, ocsp, msva]

    # TODO: check extra requirements (e.g. specific modules)

    # TODO: add hook to modify environment (unless made obsolete by
    # parameters)

    # If VERBOSE is enabled, log the HTTPD build configuration
    if 'VERBOSE' in os.environ:
        apache2 = os.environ.get('APACHE2', 'apache2')
        subprocess.run([apache2, '-f', f'{srcdir}/base_apache.conf', '-V'],
                       check=True)

    if 'USE_MSVA' in os.environ:
        os.environ['MONKEYSPHERE_VALIDATION_AGENT_SOCKET'] = \
            f'http://127.0.0.1:{os.environ["MSVA_PORT"]}'

    with contextlib.ExitStack() as service_stack:
        service_stack.enter_context(lockfile('test.lock', nolock='MGS_NETNS_ACTIVE' in os.environ))
        service_stack.enter_context(ocsp.run())
        service_stack.enter_context(backend.run())
        service_stack.enter_context(msva.run())

        # TEST_SERVICE_MAX_WAIT is in milliseconds
        wait_timeout = \
            int(os.environ.get('TEST_SERVICE_MAX_WAIT', 10000)) / 1000
        for s in bg_services:
            if s.condition():
                s.wait_ready(timeout=wait_timeout)

        # special case: expected to fail in a few cases
        try:
            service_stack.enter_context(apache.run())
            if os.path.exists(os.path.join(testdir, 'fail.server')):
                raise TestExpectationFailed(
                    'Server start did not fail as expected!')
            apache.wait_ready()
        except subprocess.CalledProcessError as e:
            if os.path.exists(os.path.join(testdir, 'fail.server')):
                print('Apache server failed to start as expected',
                      file=sys.stderr)
            else:
                raise e

        # Set TEST_TARGET for the request. Might be replaced with a
        # parameter later.
        if 'TARGET_IP' in os.environ:
            os.environ['TEST_TARGET'] = os.environ['TARGET_IP']
        else:
            os.environ['TEST_TARGET'] = os.environ['TEST_HOST']

        # Run the test connections
        with contextlib.ExitStack() as stack:
            log_file = None
            output_file = None
            if args.log_connection:
                log_file = stack.enter_context(open(args.log_connection, 'w'))
            if args.log_responses:
                output_file = stack.enter_context(open(args.log_responses, 'w'))

            if plugin.run_connection:
                plugin.run_connection(testname,
                                      conn_log=log_file,
                                      response_log=output_file)
            else:
                test_conf = stack.enter_context(
                    open(os.path.join(testdir, 'test.yml'), 'r'))
                run_test_conf(test_conf,
                              float(os.environ.get('TEST_QUERY_TIMEOUT', 5.0)),
                              conn_log=log_file, response_log=output_file)

    # run extra checks the test's hooks.py might define
    if plugin.post_check:
        log_file = None
        output_file = None
        with contextlib.ExitStack() as stack:
            # TODO: The log files should be created as temporary
            # files if needed by the plugin but not configured.
            if args.log_connection:
                log_file = stack.enter_context(open(args.log_connection, 'r'))
            if args.log_responses:
                output_file = stack.enter_context(open(args.log_responses, 'r'))
            plugin.post_check(conn_log=log_file, response_log=output_file)
