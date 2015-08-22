#!/bin/bash

# Initialize the SoftHSM token with the given label
function init_token
{
    local token_label="${1}"

    ${softhsm} --init-token --slot 0 --label "${token_label}" \
	--so-pin "${so_pin}" --pin "${GNUTLS_PIN}"
}

# Put a private key into the token with the given label
function store_privkey
{
    local token="${1}"
    local keyfile="${2}"
    local label="${3}"

    p11tool --provider=${softhsm_lib} --login --write --label "${label}" \
	    --load-privkey "${keyfile}" "${token}"
}

# Put a certificate into the token with the given label
function store_cert
{
    local token="${1}"
    local certfile="${2}"
    local label="${3}"

    p11tool --provider=${softhsm_lib} --login --write --no-mark-private \
	    --label "${label}" --load-certificate "${certfile}" "${token}"
}

# Get the URL of the SoftHSM token
function get_token_url
{
    local label="${1}"
    p11tool --provider=${softhsm_lib} --list-tokens | \
	grep -o -P "(?<=URL:\s)(.*token=${label}.*)$"
}

# Get the PKCS #11 URL for the object with the given name
# Usage: get_object_url TOKEN OBJECTNAME
function get_object_url
{
    p11tool --provider=${softhsm_lib} --list-all --login "${1}" | \
	grep -o -P "(?<=URL:\s)(.*object=${2}.*)$"
}

# Initialize the token and store the given key and certificate
# Usage: prepare_token TOKEN_LABEL PRIVKEY CERTIFICATE
function prepare_token
{
    local token_label="${1}"
    local privkey="${2}"
    local certificate="${3}"

    init_token "${token_label}"
    token=$(get_token_url ${token_label})
    store_privkey "${token}" "${privkey}" "${key_label}"
    store_cert "${token}" "${certificate}" "${cert_label}"
}



# try to find SoftHSM
softhsm="$(which softhsm)"

case "${1}" in
    (init)
	init="true"
	# If SoftHSM is not available, there's nothing to init. Just
	# exit.
	if [ -z "${softhsm}" ]; then
	    echo "SoftHSM not found, PKCS #11 test(s) will be skipped."
	    exit 0
	fi
	;;
    (*)
	# Skip the test case if SoftHSM is not available.
	if [ -z "${softhsm}" ]; then
	    echo "SoftHSM not found, skipping test."
	    exit 77
	fi
	;;
esac

set -e

# Guess location of libsofthsm based on softhsm binary. The path
# matches SoftHSM upstream, but this might fail if someone changes the
# libdir or bindir of the SoftHSM installation independently of its
# general prefix.
softhsm_prefix="$(realpath $(dirname ${softhsm})/..)"
softhsm_lib="${softhsm_prefix}/lib/softhsm/libsofthsm.so"

# fail if SOFTHSM_CONF is not set
if [ -z "${SOFTHSM_CONF}" ]; then
    echo "ERROR: SOFTHSM_CONF not set!" 1>&2
    exit 1
else
    export SOFTHSM_CONF
fi
echo "using SOFTHSM_CONF=\"${SOFTHSM_CONF}\""

# variables for token configuration
token_label="mod_gnutls-test"
so_pin="123456"
export GNUTLS_PIN="1234"
key_label="privkey"
cert_label="certificate"

if [ "${init}" = "true" ]; then
    prepare_token "${token_label}" "${2}" "${3}"
    exit 0
fi

token=$(get_token_url ${token_label})

# environment variables for the Apache configuration
export P11_KEY_URL="$(get_object_url ${token} ${key_label})"
export P11_CERT_URL="$(get_object_url ${token} ${cert_label})"
export P11_PIN="${GNUTLS_PIN}"
