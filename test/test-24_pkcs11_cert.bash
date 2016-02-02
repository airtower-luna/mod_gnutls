#!/bin/bash

testdir="$(dirname ${0})/tests/24_pkcs11_cert"

# The Apache/SoftHSM configuration mixes up directories, so generate a
# config file with an absolute path to the token database from a
# template. Generating it on every run avoids problems if the source
# tree was moved.
tmp_softhsm_conf="$(mktemp mod_gnutls_test-XXXXXX.conf)"
function cleanup_tmpconf
{
    rm "${tmp_softhsm_conf}"
}
trap cleanup_tmpconf EXIT

cat - >"${tmp_softhsm_conf}" <<EOF
0:$(realpath $(pwd))/server/softhsm.db
EOF
export SOFTHSM_CONF="${tmp_softhsm_conf}"
echo "Generated temporary SoftHSM config ${tmp_softhsm_conf}:"
cat "${tmp_softhsm_conf}"

. $(dirname ${0})/softhsm.bash

set -e

${srcdir}/runtests t-24

cleanup_tmpconf
trap - EXIT
