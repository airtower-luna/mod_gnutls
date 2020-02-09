import os
import re
import subprocess
from mgstest import require_apache_modules, require_match
from unittest import SkipTest

def prepare_env():
    require_apache_modules('mod_http2.so')
    curl = os.environ['HTTP_CLI']
    if curl == 'no':
        raise SkipTest(f'curl not found!')
    proc = subprocess.run([curl, '-V'], stdout=subprocess.PIPE,
                          check=True, text=True)
    if not re.search(r'\bHTTP2\b', proc.stdout):
        raise SkipTest(f'{curl} does not support HTTP/2!')

def run_connection(testname, conn_log, response_log):
    """Check if HTTP/2 connections using mod_gnutls and mod_http2 work."""

    url = f'https://{os.environ["TEST_HOST"]}:{os.environ["TEST_PORT"]}' \
        '/status?auto'
    command = [os.environ['HTTP_CLI'], '--http2', '--location', '--verbose',
               '--cacert', 'authority/x509.pem', url]

    proc = subprocess.run(command,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True)
    print(proc.stderr)
    print(proc.stderr, file=conn_log)
    print(proc.stdout)
    print(proc.stdout, file=response_log)
    proc.check_returncode()

def post_check(conn_log, response_log):
    print('Checking for HTTP/2 in logged header:')
    print(require_match(re.compile(r'\bHTTP/2 200\b'), conn_log).group(0))
    print('Checking for TLS session status:')
    print(require_match(re.compile(r'^Current TLS session:\s\(TLS.*$'),
                        response_log)
          .group(0))
