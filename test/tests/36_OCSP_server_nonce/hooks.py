import os
import re
import subprocess
from mgstest import require_match
from unittest import SkipTest

def prepare_env():
    if not 'OCSP_PORT' in os.environ:
        raise SkipTest('OCSP_PORT is not set, check if openssl is available.')

def post_check(conn_log, response_log):
    print('Checking if the client actually got a stapled response:')
    print(require_match(re.compile(r'^- Options: .*OCSP status request,'),
                        conn_log).group(0))
    print('Checking if the client got a nonce in the stapled response:')
    print(require_match(
            re.compile(r'^\s*Nonce: [0-9a-fA-F]{46}$'),
            parse_ocsp_response('outputs/36-ocsp.der').split('\n')
        ).group(0))

def parse_ocsp_response(der_filename):
    command = ['ocsptool', '--response-info',
               '--infile', der_filename]
    return subprocess.check_output(command).decode()
