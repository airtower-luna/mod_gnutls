#!/bin/bash
set -e

# expected output files
log="outputs/16_view-status.log"
output="outputs/16_view-status.output"

${srcdir}/netns_py.bash ${srcdir}/runtest.py --test-number 16 \
	 --log-connection "${log}" --log-responses "${output}"

# get the cipher suite reported by gnutls-cli
cli_suite="$(grep -o -P '(?<=^-\sDescription:\s).*$' "${log}")" || true
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
