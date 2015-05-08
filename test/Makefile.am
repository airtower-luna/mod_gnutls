check_SCRIPTS = test-00_basic.bash \
	test-01_serverwide_priorities.bash \
	test-02_cache_in_vhost.bash \
	test-03_cachetimeout_in_vhost.bash \
	test-04_basic_nosni.bash \
	test-05_mismatched-priorities.bash \
	test-06_verify_sni_a.bash \
	test-07_verify_sni_b.bash \
	test-08_verify_no_sni_fallback_to_first_vhost.bash \
	test-09_verify_no_sni_fails_with_wrong_order.bash \
	test-10_basic_client_verification.bash \
	test-11_basic_client_verification_fail.bash \
	test-12_cgi_variables.bash \
	test-13_cgi_variables_no_client_cert.bash \
	test-14_basic_openpgp.bash
if USE_MSVA
check_SCRIPTS += test-15_basic_msva.bash
endif
check_SCRIPTS += test-16_view-status.bash \
	test-17_cgi_vars_large_cert.bash \
	test-18_client_verification_wrong_cert.bash \
	test-19_TLS_reverse_proxy.bash \
	test-20_TLS_reverse_proxy_client_auth.bash \
	test-21_TLS_reverse_proxy_wrong_cert.bash \
	test-22_TLS_reverse_proxy_crl_revoke.bash \
	test-23_TLS_reverse_proxy_mismatched_priorities.bash \
	test-24_pkcs11_cert.bash

TESTS = $(check_SCRIPTS)

# Test cases trying to create keys and certificates in parallel causes
# race conditions. Ensure that all keys and certificates are generated
# before tests get to run.
#
# NOTE: Once the support files have been generated, test cases can be
# run with multiple jobs, but real parallelization would require
# dynamic port assignments. At the moment, lock files ensure that only
# one Apache instance (possibly plus a proxy back end instance) is
# running at any time, so test cases actually have to wait for each
# other - just not in any particular order.
check_DATA = setup.done

# Sadly, TestMakefile breaks when trying to generate keys and
# certificates with parallel make. Until that's fixed, enforce "-j1".
setup.done:
	$(MAKE) -f TestMakefile $(AM_MAKEFLAGS) -j1 $@

MOSTLYCLEANFILES = cache/* logs/* outputs/*

clean-local:
	$(MAKE) -f TestMakefile $(AM_MAKEFLAGS) clean

check_DATA += server/softhsm.db
MOSTLYCLEANFILES += tests/24_pkcs11_cert/softhsm.conf

# The dependency on setup.done is necessary to avoid race conditions
# between multiple calls to TestMakefile for key and certificate
# generation.
server/softhsm.db: setup.done
	$(MAKE) -f TestMakefile $(AM_MAKEFLAGS) server/softhsm.db
