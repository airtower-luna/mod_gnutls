import base64
import os
import re
from mgstest import require_match, TestExpectationFailed
from mgstest.ocsp import OCSPRequest, OCSPResponse
from pathlib import Path
from unittest import SkipTest


LOGFILE = Path('logs/36_OCSP_server_nonce.ocsp.error.log')
LOGFILE_POSITION = 0


def prepare_env():
    if 'OCSP_PORT' not in os.environ:
        raise SkipTest('OCSP_PORT is not set, check if openssl is available.')

    # Seek to the end of server log
    if LOGFILE.exists():
        global LOGFILE_POSITION
        LOGFILE_POSITION = LOGFILE.stat().st_size


def post_check(conn_log, response_log):
    print('Checking if the client actually got a stapled response:')
    print(require_match(re.compile(r'^- Options: .*OCSP status request,'),
                        conn_log).group(0))

    print('Checking for outputs/36-ocsp.der:')
    ocsp_response = OCSPResponse.parse_file('outputs/36-ocsp.der')
    print(ocsp_response)

    print('Checking if the client got a nonce in the stapled response:')
    resp_nonce = ocsp_response.get_field('nonce').get_value()
    print(resp_nonce)

    print('Checking if the server log contains an OCSP request')
    with LOGFILE.open() as log:
        print(f'Seeking to position {LOGFILE_POSITION}')
        log.seek(LOGFILE_POSITION)
        ocsp_request = None

        while ocsp_request is None:
            log_match = require_match(
                re.compile(r"Received OCSP request: '([^']*)'"), log)
            test_request = OCSPRequest.parse_str(
                base64.b64decode(log_match.group(1)))
            print(repr(test_request))
            if ocsp_response.matches_request(test_request):
                print("Request matches response")
                ocsp_request = test_request
            else:
                print("Request doesn't match response")

    print('Checking if the OCSP request has a nonce')
    req_nonce = ocsp_request.get_field('nonce').get_value()
    print(req_nonce)

    print('Checking if the request and response nonces match')
    if resp_nonce != req_nonce:
        raise TestExpectationFailed('Nonce mismatch!')
