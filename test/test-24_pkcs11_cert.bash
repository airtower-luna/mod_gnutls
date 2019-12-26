#!/bin/bash

testdir="$(dirname ${0})/tests/24_pkcs11_cert"

# The Apache/SoftHSM configuration mixes up directories, so generate
# config files with absolute paths to the token database from a
# template. Generating them on every run avoids problems if the source
# tree was moved.
tmp_softhsm_conf="$(mktemp mod_gnutls_test-XXXXXX.conf)"
function cleanup_tmpconf
{
    rm "${tmp_softhsm_conf}"
}
trap cleanup_tmpconf EXIT

if [ "${SOFTHSM_MAJOR_VERSION}" = "1" ]; then
    cat - >"${tmp_softhsm_conf}" <<EOF
0:$(realpath $(pwd))/server/softhsm.db
EOF
    export SOFTHSM_CONF="${tmp_softhsm_conf}"
elif [ "${SOFTHSM_MAJOR_VERSION}" = "2" ]; then
    cat - >"${tmp_softhsm_conf}" <<EOF
objectstore.backend = file
directories.tokendir = $(realpath $(pwd))/authority/server/softhsm2.db
EOF
    export SOFTHSM2_CONF="${tmp_softhsm_conf}"
fi

echo "Generated temporary SoftHSM config ${tmp_softhsm_conf}:"
cat "${tmp_softhsm_conf}"

. $(dirname ${0})/softhsm.bash

set -e

${srcdir}/netns_py.bash ${srcdir}/runtest.py --test-number 24

cleanup_tmpconf
trap - EXIT
