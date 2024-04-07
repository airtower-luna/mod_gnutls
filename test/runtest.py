#!/usr/bin/python3
# PYTHON_ARGCOMPLETE_OK

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

import asyncio
import contextlib
import itertools
import os
import subprocess
import sys
import tempfile
import yaml
from pathlib import Path
from unittest import SkipTest

import mgstest.hooks
import mgstest.valgrind
from mgstest import lockfile, TestExpectationFailed
from mgstest.services import ApacheService, TestService
from mgstest.tests import run_test_conf


def find_testdir(number, dir):
    """Find the configuration directory for a test based on its
    number. The given directory must contain exactly one directory
    with a name matching "NUMBER_*", otherwise a LookupError is
    raised.

    """
    found = None
    for entry in dir.iterdir():
        if entry.is_dir():
            num = int(entry.name.split('_', maxsplit=1)[0])
            if number == num:
                if found:
                    # duplicate numbers are an error
                    raise LookupError('Multiple directories found for '
                                      f'test number {number}: '
                                      f'{found.name} and {entry.name}')
                else:
                    found = entry
    if found is None:
        raise LookupError('No test directory found for test number '
                          f'{number}!')
    return found, found.name


def temp_logfile():
    return tempfile.SpooledTemporaryFile(max_size=4096, mode='w+',
                                         prefix='mod_gnutls', suffix=".log")


async def check_ocsp_responder():
    # Check if OCSP responder works
    issuer_cert = f'{os.environ.get("PWD", ".")}/authority/x509.pem'
    check_cert = f'{os.environ.get("PWD", ".")}/authority/server/x509.pem'
    print(
        'ocsptool', '--ask', '--nonce',
        '--load-issuer', issuer_cert, '--load-cert', check_cert,
        file=sys.stderr)
    proc = await asyncio.create_subprocess_exec(
        'ocsptool', '--ask', '--nonce',
        '--load-issuer', issuer_cert, '--load-cert', check_cert)
    return (await proc.wait()) == 0


async def check_msva():
    # Check if MSVA is up
    cert_file = 'authority/client/x509.pem'
    uid_file = 'authority/client/uid'
    with open(uid_file, 'r') as file:
        uid = file.read().strip()
    with open(cert_file, 'r') as cert:
        proc = await asyncio.create_subprocess_exec(
            'msva-query-agent', 'https', uid, 'x509pem', 'client',
            stdin=cert)
        return (await proc.wait()) == 0


async def main(args):
    # The Automake environment always provides srcdir, the default is
    # for manual use.
    srcdir = Path(os.environ.get('srcdir', '.')).resolve()
    # ensure environment srcdir is absolute
    os.environ['srcdir'] = str(srcdir)

    # Find the configuration directory for the test in
    # ${srcdir}/tests/, based on the test number.
    testdir, testname = find_testdir(args.test_number, srcdir / 'tests')
    print(f'Found test {testname}, test dir is {testdir}')
    os.environ['TEST_NAME'] = testname

    # Load test config
    try:
        with open(testdir / 'test.yaml', 'r') as conf_file:
            test_conf = yaml.load(conf_file, Loader=yaml.Loader)
    except FileNotFoundError:
        test_conf = None

    # Load test case hooks (if any)
    plugin = mgstest.hooks.load_hooks_plugin(testdir / 'hooks.py')

    valgrind_log = None
    if args.valgrind:
        valgrind_log = Path('logs', f'valgrind-{testname}.log')

    # Define the available services
    apache = ApacheService(
        config=testdir / 'apache.conf',
        pidfile=f'{os.environ.get("PWD", ".")}/apache2-{testname}.pid',
        valgrind_log=valgrind_log,
        valgrind_suppress=args.valgrind_suppressions)
    backend = ApacheService(
        config=testdir / 'backend.conf',
        pidfile=f'backend-{testname}.pid')
    ocsp = ApacheService(
        config=testdir / 'ocsp.conf',
        pidfile=f'ocsp-{testname}.pid',
        check=check_ocsp_responder)
    msva = TestService(
        start=['monkeysphere-validation-agent'],
        env={'GNUPGHOME': 'msva.gnupghome',
             'MSVA_KEYSERVER_POLICY': 'never'},
        condition=lambda: 'USE_MSVA' in os.environ,
        check=check_msva)

    # background services: must be ready before the main apache
    # instance is started
    bg_services = [backend, ocsp, msva]

    # If VERBOSE is enabled, log the HTTPD build configuration
    if 'VERBOSE' in os.environ:
        apache2 = os.environ.get('APACHE2', 'apache2')
        subprocess.run([apache2, '-f', f'{srcdir}/base_apache.conf', '-V'],
                       check=True)

    # This hook may modify the environment as needed for the test.
    cleanup_callback = None
    try:
        if plugin.prepare_env:
            cleanup_callback = plugin.prepare_env()
    except SkipTest as skip:
        print(f'Skipping: {skip!s}')
        sys.exit(77)

    if 'USE_MSVA' in os.environ:
        os.environ['MONKEYSPHERE_VALIDATION_AGENT_SOCKET'] = \
            f'http://127.0.0.1:{os.environ["MSVA_PORT"]}'

    async with contextlib.AsyncExitStack() as service_stack:
        if cleanup_callback:
            service_stack.callback(cleanup_callback)
        if 'MGS_NETNS_ACTIVE' not in os.environ:
            service_stack.enter_context(lockfile('test.lock'))

        wait_timeout = float(os.environ.get('TEST_SERVICE_MAX_WAIT', 10))
        await asyncio.gather(*(
            asyncio.create_task(
                service_stack.enter_async_context(
                    s.run(ready_timeout=wait_timeout)))
            for s in bg_services))

        # special case: expected to fail in a few cases
        await service_stack.enter_async_context(apache.run())
        failed = await apache.wait_ready()
        if (testdir / 'fail.server').is_file():
            if failed:
                print('Apache server failed to start as expected',
                      file=sys.stderr)
            else:
                raise TestExpectationFailed(
                    'Server start did not fail as expected!')

        # Set TEST_TARGET for the request. Might be replaced with a
        # parameter later.
        if 'TARGET_IP' in os.environ:
            os.environ['TEST_TARGET'] = os.environ['TARGET_IP']
        else:
            os.environ['TEST_TARGET'] = os.environ['TEST_HOST']

        # Run the test connections
        if plugin.run_connection:
            plugin.run_connection(testname,
                                  conn_log=args.log_connection,
                                  response_log=args.log_responses)
        else:
            run_test_conf(test_conf,
                          float(os.environ.get('TEST_QUERY_TIMEOUT', 5.0)),
                          conn_log=args.log_connection,
                          response_log=args.log_responses)

        await asyncio.wait(
            {asyncio.create_task(s.stop())
             for s in itertools.chain([apache], bg_services)})

    # run extra checks the test's hooks.py might define
    if plugin.post_check:
        args.log_connection.seek(0)
        args.log_responses.seek(0)
        plugin.post_check(conn_log=args.log_connection,
                          response_log=args.log_responses)

    if valgrind_log:
        with open(valgrind_log) as log:
            errors = mgstest.valgrind.error_summary(log)
            print(f'Valgrind summary: {errors[0]} errors, '
                  f'{errors[1]} suppressed')
            if errors[0] > 0:
                sys.exit(ord('V'))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description='Run a mod_gnutls server test')
    parser.add_argument('--test-number', type=int,
                        required=True, help='load YAML test configuration')
    parser.add_argument('--log-connection', type=argparse.FileType('w+'),
                        default=temp_logfile(),
                        help='write connection log to this file')
    parser.add_argument('--log-responses', type=argparse.FileType('w+'),
                        default=temp_logfile(),
                        help='write HTTP responses to this file')
    parser.add_argument('--valgrind', action='store_true',
                        help='run primary Apache instance with Valgrind')
    parser.add_argument('--valgrind-suppressions', action='append',
                        default=[],
                        help='use Valgrind suppressions file')

    # enable bash completion if argcomplete is available
    try:
        import argcomplete
        argcomplete.autocomplete(parser)
    except ImportError:
        pass

    args = parser.parse_args()

    with contextlib.ExitStack() as stack:
        stack.enter_context(contextlib.closing(args.log_connection))
        stack.enter_context(contextlib.closing(args.log_responses))
        asyncio.run(main(args))
