#!/bin/bash

testdir="./tests/24_pkcs11_cert"
. ./softhsm.bash

set -e

make -f TestMakefile t-24
