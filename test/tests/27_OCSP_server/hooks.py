import os
import re
from mgstest import require_match
from unittest import SkipTest


def prepare_env():
    if 'OCSP_PORT' not in os.environ:
        raise SkipTest('OCSP_PORT is not set, check if openssl is available.')


def post_check(conn_log, response_log):
    print('Checking if the client actually got a stapled response:')
    print(require_match(re.compile(r'^- Options: .*OCSP status request,'),
                        conn_log).group(0))
