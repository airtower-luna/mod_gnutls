import os
import re
import subprocess
import tempfile
from mgstest import require_match
from unittest import SkipTest


def prepare_env():
    curl = os.environ.get('CURL')
    if curl is None:
        raise SkipTest('curl not found!')


def run_connection(testname, conn_log, response_log) -> None:
    """Check if client authentication with a certificate chain beyond
    buffer size is rejected."""

    url = f'https://{os.environ["TEST_HOST"]}:{os.environ["TEST_PORT"]}' \
        '/test.txt'

    with tempfile.NamedTemporaryFile() as tmpcert:
        with open('authority/client/x509.pem', 'rb') as fh:
            pem = fh.read()
        for _ in range(9):
            tmpcert.write(pem)
            tmpcert.write(b'\n')
        tmpcert.flush()
        command = [
            os.environ['CURL'], '--verbose',
            '--cacert', 'authority/x509.pem',
            '--cert', tmpcert.name,
            '--key', 'authority/client/secret.key',
            url
        ]
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True)
    print(proc.stderr)
    print(proc.stderr, file=conn_log)
    print(proc.stdout)
    print(proc.stdout, file=response_log)
    proc.check_returncode()


def post_check(conn_log, response_log):
    print('Checking for HTTP 403 Forbidden response:')
    print(require_match(
        re.compile(r'\bHTTP/[\.\d]+ 403 Forbidden\b'),
        conn_log).group(0))
