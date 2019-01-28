#!/bin/bash
set -e
${srcdir}/runtests t-16

# expected output file
output="outputs/16_view-status.output"
# get the cipher suite reported by gnutls-cli
cli_suite="$(grep -o -P '(?<=^-\sDescription:\s).*$' "${output}")" || true
# extract cipher suite from the server status output
status_suite="$(grep -o -P '(?<=^Current TLS session:\s).*$' "${output}")" \
    || true

echo
if [[ -n "${cli_suite}" && "${status_suite}" = "${cli_suite}" ]]; then
    echo "Server and client report matching cipher suite: ${status_suite}"
else
    echo "ERROR: Cipher suites mismatching or missing!"
    echo "Server: '${status_suite}'"
    echo "Client: '${cli_suite}'"
    exit 1
fi
