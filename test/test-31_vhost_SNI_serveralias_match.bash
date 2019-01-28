#!/bin/bash
set -e
: ${srcdir:="."}
. ${srcdir}/common.bash

require_gnutls_cli 3.5.12 || (echo "Using --sni-hostname requires gnutls-cli version 3.5.12 or newer"; exit 77)
${srcdir}/runtests t-31
