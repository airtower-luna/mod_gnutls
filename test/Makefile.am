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
	test-24_pkcs11_cert.bash \
	test-25_Disable_TLS_1.0.bash \
	test-26_HTTPS_server_var.bash

TESTS = $(dist_check_SCRIPTS)

# Identities in the miniature CA, server, and client environment for
# the test suite
shared_identities = server authority client imposter rogueca
pgp_identities = $(shared_identities)
x509_only_identities = rogueclient
x509_identities = $(shared_identities) $(x509_only_identities)
identities = $(shared_identities) $(x509_only_identities)
# Append strings after ":=" to each identity to generate a list of
# necessary files
pgp_tokens = $(pgp_identities:=/secring.gpg) $(pgp_identities:=/cert.pgp) \
	$(pgp_identities:=/secret.pgp)
x509_keys = $(x509_identities:=/secret.key)
x509_certs = $(x509_identities:=/x509.pem)
x509_tokens = $(x509_certs) $(x509_keys)
tokens = $(x509_tokens) $(pgp_tokens)

if !DISABLE_FLOCK
# flock command for write access to the authority keyring
GPG_FLOCK = $(FLOCK) authority/lock
endif

include $(srcdir)/test_ca.mk

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
check_DATA = $(tokens) server/crl.pem

MOSTLYCLEANFILES = cache/* logs/* outputs/* server/crl.pem

cert_templates = authority.template.in client.template.in \
	imposter.template.in rogueca.template rogueclient.template.in \
	server.template.in
generated_templates = authority.template client.template \
	imposter.template rogueclient.template server.template

# Delete X.509 private keys on full clean. Note that unless you need
# to generate fresh keys, the "mostlyclean" target should be
# sufficient (see below).
CLEANFILES = $(x509_keys)

# Delete X.509 certificates and generated templates on "mostlyclean"
# target. Certificates can be rebuilt without generating new key
# pairs, and regenerating them makes it possible to change identities
# (e.g. host names) without wasting time on new keys (which would
# happen after "clean").
MOSTLYCLEANFILES += */x509.pem $(generated_templates) *.uid


# Delete PGP keyrings on "mostlyclean" target. They are created from
# the X.509 private keys and certificates with an expiration time of
# one day, so regenerating them is both fast and frequently
# necessary.
MOSTLYCLEANFILES += */*.pgp */*.gpg */*.gpg~ */gpg.conf authority/lock
# GnuPG random pool, no need to regenerate on every build
CLEANFILES += authority/random_seed

# Delete lock files for test servers on "mostlyclean" target.
MOSTLYCLEANFILES += *.lock

# rule to build MSVA trust database
if USE_MSVA
msva_home = msva.gnupghome
check_DATA += $(msva_home)/trustdb.gpg client.uid
MOSTLYCLEANFILES += $(msva_home)/trustdb.gpg
$(msva_home)/trustdb.gpg: authority/minimal.pgp client/cert.pgp
	mkdir -p -m 0700 $(dir $@)
	GNUPGHOME=$(dir $@) gpg --import < $<
	printf "%s:6:\n" "$$(GNUPGHOME=authority gpg --with-colons --list-secret-keys --fingerprint | grep ^fpr: | cut -f 10 -d :)" | GNUPGHOME=$(dir $@) gpg --import-ownertrust
	GNUPGHOME=$(dir $@) gpg --import < client/cert.pgp
	printf "keyserver does-not-exist.example\n" > $(msva_home)/gpg.conf
endif

# SoftHSM files
check_DATA += server/softhsm.db
MOSTLYCLEANFILES += tests/24_pkcs11_cert/softhsm.conf server/softhsm.db


check_DATA += make-test-dirs
extra_dirs = logs cache outputs
make-test-dirs:
	mkdir -p $(extra_dirs)
.PHONY: make-test-dirs

clean-local:
	-rmdir $(identities) || true
	-rmdir $(extra_dirs) || true
if USE_MSVA
	-rmdir $(msva_home) || true
endif

# Apache configuration and data files
apache_data = base_apache.conf cgi_module.conf data/* mime.types proxy_mods.conf

EXTRA_DIST = $(apache_data) $(cert_templates) *.uid.in common.bash \
	proxy_backend.bash runtests server-crl.template server-softhsm.conf \
	softhsm.bash

# Lockfile for the main Apache process
test_lockfile = ./test.lock
# Lockfile for the proxy backend Apache process (if any)
backend_lockfile = ./backend.lock
# Maximum wait time in seconds for flock to aquire instance lock
# files, or Apache to remove its PID file
lock_wait = 30

# port for the main Apache server
TEST_PORT ?= 9932
# port for MSVA in test cases that use it
MSVA_PORT ?= 9933
# maximum time to wait for MSVA startup (milliseconds)
TEST_MSVA_MAX_WAIT ?= 10000
# wait loop time for MSVA startup (milliseconds)
TEST_MSVA_WAIT ?= 400
# seconds for the HTTP request to be sent and responded to
TEST_QUERY_DELAY ?= 30

AM_TESTS_ENVIRONMENT = export APACHE2=$(APACHE2); \
	export AP_LIBEXECDIR=$(AP_LIBEXECDIR); \
	export TEST_LOCK_WAIT="$(lock_wait)"; \
	export TEST_HOST="$(TEST_HOST)"; \
	export TEST_PORT="$(TEST_PORT)"; \
	export MSVA_PORT="$(MSVA_PORT)"; \
	export TEST_MSVA_MAX_WAIT="$(TEST_MSVA_MAX_WAIT)"; \
	export TEST_MSVA_WAIT="$(TEST_MSVA_WAIT)"; \
	export TEST_QUERY_DELAY="$(TEST_QUERY_DELAY)"; \
	export BACKEND_HOST="$(TEST_HOST)";

if ENABLE_NETNS
AM_TESTS_ENVIRONMENT += export UNSHARE="$(UNSHARE)"; \
	export USE_TEST_NAMESPACE=1;
endif
# Without flock tests must not run in parallel. Otherwise set lock files.
if DISABLE_FLOCK
.NOTPARALLEL:
else
AM_TESTS_ENVIRONMENT += export FLOCK="$(FLOCK)"; \
	export TEST_LOCK="$(test_lockfile)"; \
	export BACKEND_LOCK="$(backend_lockfile)";
endif

# Echo AM_TESTS_ENVIRONMENT. This can be useful for debugging, e.g. if
# you want to manually run an Apache instance with Valgrind using the
# same configuration as a test case.
show-test-env: export TEST_ENV=$(AM_TESTS_ENVIRONMENT)
show-test-env:
	@echo "$${TEST_ENV}"
