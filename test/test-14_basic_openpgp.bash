#!/bin/bash
./gnutls_openpgp_support || exit $?
${srcdir}/runtests t-14
