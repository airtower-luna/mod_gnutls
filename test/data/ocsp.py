#!/usr/bin/python3
# Python 3 wrapper to use "openssl ocsp" as a simple OCSP responder
#
# Copyright 2020 Krista Karppinen, Fiona Klute
#
# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License.  You
# may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

# This is a CGI script to run the OpenSSL OCSP responder from a web
# server. The CGI environment must provide the following four
# variables to configure the OCSP responder:
#
# CA_CERT: CA certificate of the CA that issued the certificates this
# OCSP reponder should provide status information for
#
# OCSP_INDEX: CA index file in the format used by OpenSSL
#
# OCSP_CERT: Certificate that should be used to sign OCSP reponses
# (either CA_CERT or a dedicated OCSP signer certificate, see RFC
# 6960, Section 4.2.2.2)
#
# OCSP_KEY: Private key for OCSP_CERT
#
# Additionally, the OpenSSL binary to use can be configured through
# the OPENSSL environment variable. If it is not set, the PATH will be
# searched.

from http import HTTPStatus
import base64
import os
import shutil
import subprocess
import sys


REQUEST_TYPE = 'application/ocsp-request'
RESPONSE_TYPE = 'application/ocsp-response'


def stdout(data):
    sys.stdout.buffer.write(data)


def stdout_line(line):
    stdout(line.encode('utf-8'))
    stdout(b'\n')


def stdout_status(status, content_type='text/plain'):
    stdout_line(f'Status: {status.value} {status.phrase}')
    stdout_line(f'Content-Type: {content_type}\n')


def stdout_response(status, response):
    stdout_status(status, content_type=RESPONSE_TYPE)
    stdout(response)


def handle_get():
    # GET OCSP requests are allowed by RFC 6960, Appendix A.1, but
    # not implemented here. It should be possible to extract a GET
    # request from the PATH_INFO CGI variable.
    stdout_status(HTTPStatus.METHOD_NOT_ALLOWED)
    stdout_line('OCSP GET request not implemented.')


def handle_post():
    content_type = os.getenv('CONTENT_TYPE')
    content_length = os.getenv('CONTENT_LENGTH')
    if content_type != REQUEST_TYPE or not content_length:
        stdout_status(HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
        stdout_line(f'POST request must contain {REQUEST_TYPE} data.')
        return

    try:
        req = sys.stdin.buffer.read(int(content_length))
        print(f'Received OCSP request: \'{base64.b64encode(req).decode()}\'',
              file=sys.stderr, flush=True)
        openssl = os.getenv('OPENSSL') or shutil.which('openssl')
        openssl_run = subprocess.run(
            [openssl, 'ocsp',
             '-index', os.getenv('OCSP_INDEX'),
             '-CA', os.getenv('CA_CERT'),
             '-rsigner', os.getenv('OCSP_CERT'),
             '-rkey', os.getenv('OCSP_KEY'),
             '-nmin', os.getenv('OCSP_VALID_MIN', '5'),
             '-reqin', '-', '-respout', '-'],
            input=req, capture_output=True)

        if openssl_run.returncode == 0:
            stdout_response(HTTPStatus.OK, openssl_run.stdout)
            sys.stderr.buffer.write(openssl_run.stderr)
        else:
            raise Exception('openssl process exited with return code '
                            f'{openssl_run.returncode}, stdout: '
                            f'{openssl_run.stdout}, stderr: '
                            f'{openssl_run.stderr}')
    except:
        stdout_status(HTTPStatus.INTERNAL_SERVER_ERROR)
        raise


if __name__ == '__main__':
    method = os.getenv('REQUEST_METHOD')
    if method == 'GET':
        handle_get()
    elif method == 'POST':
        handle_post()
    else:
        stdout_status(HTTPStatus.METHOD_NOT_ALLOWED)
