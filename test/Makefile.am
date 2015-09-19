SUBDIRS = tests

dist_check_SCRIPTS = test-00_basic.bash \
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
dist_check_SCRIPTS += test-15_basic_msva.bash
endif
dist_check_SCRIPTS += test-16_view-status.bash \
	test-17_cgi_vars_large_cert.bash \
	test-18_client_verification_wrong_cert.bash \
	test-19_TLS_reverse_proxy.bash \
	test-20_TLS_reverse_proxy_client_auth.bash \
	test-21_TLS_reverse_proxy_wrong_cert.bash \
	test-22_TLS_reverse_proxy_crl_revoke.bash \
	test-23_TLS_reverse_proxy_mismatched_priorities.bash \
	test-24_pkcs11_cert.bash

TESTS = $(dist_check_SCRIPTS)

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
check_DATA = setup.done server/crl.pem

MOSTLYCLEANFILES = cache/* logs/* outputs/* server/crl.pem

cert_templates = authority.template.in client.template.in \
	imposter.template.in rogueca.template server.template.in
generated_templates = authority.template client.template \
	imposter.template server.template

# Delete X.509 certificates and generated templates on "mostlyclean"
# target. Certificates can be rebuilt without generating new key
# pairs, and regenerating them makes it possible to change identities
# (e.g. host names) without wasting entropy on new keys (which would
# happen after "clean").
MOSTLYCLEANFILES += */x509.pem $(generated_templates)

# Delete PGP keyrings on "mostlyclean" target. They are created from
# the X.509 private keys and certificates with an expiration time of
# one day, so regenerating them is both fast and frequently
# necessary.
MOSTLYCLEANFILES += */*.pgp */*.gpg */*.gpg~ */gpg.conf

clean-local:
	$(MAKE) -f $(srcdir)/TestMakefile $(AM_MAKEFLAGS) clean

# SoftHSM files
check_DATA += server/softhsm.db
MOSTLYCLEANFILES += tests/24_pkcs11_cert/softhsm.conf

# This rule can be used for any TestMakefile target not included in
# setup.done. The dependency on setup.done is used to avoid race
# conditions between multiple calls to TestMakefile for key and
# certificate generation. It is ignored for setup.done itself.
.PHONY: setup.done
server/crl.pem server/softhsm.db setup.done: setup.done
	TEST_HOST="$(TEST_HOST)" TEST_IP="$(TEST_IP)" srcdir=$(srcdir) \
	$(MAKE) -f $(srcdir)/TestMakefile $(AM_MAKEFLAGS) $@

apache_data = base_apache.conf cgi_module.conf data/* mime.types proxy_mods.conf

EXTRA_DIST = $(apache_data) $(cert_templates) *.uid.in proxy_backend.bash \
	runtests server-crl.template server-softhsm.conf softhsm.bash \
	TestMakefile

# Lockfile for the main Apache process
test_lockfile = ./test.lock
# Maximum wait time in seconds for flock to aquire instance lock files
lock_wait = 30

# port for the main Apache server
TEST_PORT ?= 9932
# port for MSVA in test cases that use it
MSVA_PORT ?= 9933
# maximum time to wait for MSVA startup
TEST_MSVA_MAX_WAIT ?= 10
# wait loop time for MSVA startup
TEST_MSVA_WAIT ?= 0.4
# seconds for the HTTP request to be sent and responded to
TEST_QUERY_DELAY ?= 30

AM_TESTS_ENVIRONMENT = export APACHE2=$(APACHE2); \
	export AP_LIBEXECDIR=$(AP_LIBEXECDIR); \
	export TEST_LOCK="$(test_lockfile)"; \
	export TEST_LOCK_WAIT="$(lock_wait)"; \
	export TEST_HOST="$(TEST_HOST)"; \
	export TEST_IP="$(TEST_IP)"; \
	export TEST_PORT="$(TEST_PORT)"; \
	export MSVA_PORT="$(MSVA_PORT)"; \
	export TEST_MSVA_MAX_WAIT="$(TEST_MSVA_MAX_WAIT)"; \
	export TEST_MSVA_WAIT="$(TEST_MSVA_WAIT)"; \
	export TEST_QUERY_DELAY="$(TEST_QUERY_DELAY)"; \
	export BACKEND_HOST="$(TEST_HOST)"; \
	export BACKEND_IP="$(TEST_IP)";

# Echo AM_TESTS_ENVIRONMENT. This can be useful for debugging, e.g. if
# you want to manually run an Apache instance with Valgrind using the
# same configuration as a test case.
show-test-env: export TEST_ENV=$(AM_TESTS_ENVIRONMENT)
show-test-env:
	@echo "$${TEST_ENV}"
