#!/bin/bash
# CGI wrapper to use "openssl ocsp" as a simple OCSP responder
#
# Copyright 2016 Thomas Klute
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

if [ -z "${OPENSSL}" ]; then
    OPENSSL=$(which openssl)
fi

case "${REQUEST_METHOD}" in
    ("GET")
	# GET OCSP requests are allowed by RFC 6960, Appendix A.1, but
	# not implemented here. It should be possible to extract a GET
	# request from the PATH_INFO CGI variable.
	echo "Status: 405 Method Not Allowed"
	echo -e "Content-Type: text/plain\n"
	echo "OCSP GET request not implemented."
	;;
    ("POST")
	if [ "${CONTENT_TYPE}" == "application/ocsp-request" ] &&
	       [ ! -z "${CONTENT_LENGTH}" ]; then
	    echo "Status: 200 OK"
	    echo -e "Content-Type: application/ocsp-response\n"
	    ${OPENSSL} ocsp -index "${OCSP_INDEX}" -CA "${CA_CERT}" \
		    -rsigner "${OCSP_CERT}" -rkey "${OCSP_KEY}" \
		    -nmin 3 -reqin - -respout -
	else
	    echo "Status: 415 Unsupported Media Type"
	    echo -e "Content-Type: text/plain\n"
	    echo "POST request must contain application/ocsp-request data."
	fi
	;;
    (*)
	echo "Status: 405 Method Not Allowed"
	echo -e "Content-Type: text/plain\n"
	;;
esac
