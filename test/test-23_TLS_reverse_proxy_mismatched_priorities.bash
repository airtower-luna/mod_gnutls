#!/bin/bash

# This test checks if server and proxy priorities are applied
# properly. The proxy server requries a TLS 1.2 connection, but the
# back end server is configured not to use TLS 1.2. The proxy request
# must fail and the client must receive an error message to pass.
${srcdir}/runtests t-23
