#!/bin/bash
cat <<EOF
Content-Type: text/plain

----Certificate:----
$SSL_CLIENT_CERT

----Verification Status:----
$SSL_CLIENT_VERIFY

----SubjectAltName:----
$SSL_CLIENT_S_AN0

DH prime bits: $SSL_DH_PRIME_BITS
EOF
