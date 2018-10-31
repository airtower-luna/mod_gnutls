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
	test-14_resume_session.bash
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
	test-26_redirect_HTTP_to_HTTPS.bash \
	test-27_OCSP_server.bash \
	test-28_HTTP2_support.bash \
	test-29_force_handshake_vhost.bash \
	test-30_ip_based_vhosts.bash

TEST_EXTENSIONS = .bash
TESTS = $(dist_check_SCRIPTS)

check_PROGRAMS = pgpcrc
pgpcrc_SOURCES = pgpcrc.c

# build OCSP database tool
if ENABLE_OCSP_TEST
check_PROGRAMS += gen_ocsp_index
gen_ocsp_index_SOURCES = gen_ocsp_index.c cert_helper.c
gen_ocsp_index_CFLAGS = $(LIBGNUTLS_CFLAGS)
gen_ocsp_index_LDFLAGS = $(LIBGNUTLS_LIBS)
noinst_HEADERS = cert_helper.h
endif

# Identities in the miniature CA, server, and client environment for
# the test suite
shared_identities = authority client
pgp_identities = $(shared_identities)
x509_only_identities = server rogueca imposter rogueclient
if ENABLE_OCSP_TEST
x509_only_identities += ocsp-responder
endif
x509_identities = $(shared_identities) $(x509_only_identities)
identities = $(shared_identities) $(x509_only_identities)
# Append strings after ":=" to each identity to generate a list of
# necessary files
pgp_tokens = $(pgp_identities:=/cert.pgp) \
	$(pgp_identities:=/secret.pgp)
x509_keys = $(x509_identities:=/secret.key)
x509_certs = $(x509_identities:=/x509.pem)
x509_tokens = $(x509_certs) $(x509_keys)
tokens = $(x509_tokens) $(pgp_tokens)

if !DISABLE_FLOCK
# flock command for write access to the authority keyring
GPG_FLOCK = @FLOCK@ authority/lock
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
	imposter.template.in ocsp-responder.template rogueca.template \
	rogueclient.template.in server.template.in
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
MOSTLYCLEANFILES += */*.pgp */*.pgp.raw */*.gpg */*.gpg~ */gpg.conf \
	authority/lock */*.kbx */*.kbx~ */S.gpg-agent */private-keys-v1.d/* \
	authority/tofu.db
# GnuPG random pool, no need to regenerate on every build
CLEANFILES += authority/random_seed

# GnuPG 2 starts gpg-agent processes per GNUPGHOME (one for every PGP
# identity) while creating the PGP certificates. This target is called
# by both "check-local" and "mostlyclean-local": The former because
# agent processes are started while preparing for "check" and are no
# longer needed afterwards, the latter to make sure they are gone
# along with their certificates.
stop-gnupg-agent:
	for id in $(pgp_identities) $(msva_home); do \
		GNUPGHOME=$$id/ gpgconf --kill gpg-agent || true; \
	done

check-local: stop-gnupg-agent

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
	printf "%s:6:\n" "$$(GNUPGHOME=authority/ gpg --with-colons --list-secret-keys --fingerprint | grep ^fpr: | cut -f 10 -d :)" | GNUPGHOME=$(dir $@) gpg --import-ownertrust
	GNUPGHOME=$(dir $@) gpg --import < client/cert.pgp
	printf "keyserver does-not-exist.example\n" > $(msva_home)/gpg.conf
endif

if ENABLE_OCSP_TEST
# rules to build OCSP database
check_DATA += authority/ocsp_index.txt
MOSTLYCLEANFILES += authority/ocsp_index.txt authority/ocsp_index.txt.attr
authority/ocsp_index.txt: $(x509_tokens) gen_ocsp_index authority/ocsp_index.txt.attr
	./gen_ocsp_index server/x509.pem client/x509.pem > $@

authority/ocsp_index.txt.attr: authority/secret.key
	echo "unique_subject = no" > $@

# build certificate chain file for server
check_DATA += server/x509-chain.pem
MOSTLYCLEANFILES += server/x509-chain.pem
%/x509-chain.pem: %/x509.pem authority/x509.pem
	cat $< authority/x509.pem > $@
endif

# SoftHSM tokens. Note that the SoftHSM 2 token is a directory and
# hence has to be treated slightly differently.
SOFTHSM_TOKEN = server/softhsm.db
SOFTHSM2_TOKEN = server/softhsm2.db

# Tokens should be cleaned whether or not the matching SoftHSM version
# was detected on the last ./configure run.
MOSTLYCLEANFILES += $(SOFTHSM_TOKEN)
# included in mostlyclean-local below
clean-softhsm2-db:
	-rm -rf $(SOFTHSM2_TOKEN)

if HAVE_SOFTHSM1
check_DATA += $(SOFTHSM_TOKEN)
endif HAVE_SOFTHSM1

if HAVE_SOFTHSM2
check_DATA += $(SOFTHSM2_TOKEN)
endif HAVE_SOFTHSM2

check_DATA += make-test-dirs
extra_dirs = logs cache outputs
make-test-dirs:
	mkdir -p $(extra_dirs)

.PHONY: make-test-dirs clean-softhsm2-db stop-gnupg-agent


mostlyclean-local: clean-softhsm2-db stop-gnupg-agent
	-rmdir $(pgp_identities:=/private-keys-v1.d) || true
if USE_MSVA
	-rmdir $(msva_home)/private-keys-v1.d || true
endif

# Delete test data directories, and wait for test services to
# exit. The reason for the wait is that Apache instances may take some
# time to exit and delete their PID files. Occasionally some PID files
# where still around during "distcheck" runs by the time the target
# checked if the build directory was really empty after "distclean",
# breaking the build. Delaying "clean-local" until PID files are gone
# avoids this issue, and the timeout will expose actually unclean
# stops.
clean-local:
	-rmdir $(identities) || true
	-rmdir $(extra_dirs) || true
if USE_MSVA
	-rmdir $(msva_home) || true
endif
	wait=0; \
	while ls *.pid && test "$$wait" -lt "@TEST_LOCK_WAIT@"; do \
		wait=$$(($$wait + 1)); \
		echo "waiting for test services to exit ($$wait seconds)"; \
		sleep 1; \
	done

# Apache configuration and data files
apache_data = base_apache.conf cgi_module.conf data/dump.cgi data/ocsp.cgi \
	data/secret.txt data/test.txt ffdhe3072.pem mime.types \
	proxy_mods.conf

EXTRA_DIST = $(apache_data) $(cert_templates) $(shared_identities:=.uid.in) \
	apache_service.bash common.bash runtests server-crl.template \
	softhsm.bash

# Lockfile for the main Apache process
test_lockfile = ./test.lock
# Lockfile for the proxy backend Apache process (if any)
backend_lockfile = ./backend.lock
# Lockfile for the OCSP server Apache process (if any)
ocsp_lockfile = ./ocsp.lock

# port for the main Apache server
TEST_PORT ?= 9932
# port for MSVA in test cases that use it
MSVA_PORT ?= 9933
# port for TLS proxy backend server
BACKEND_PORT ?= 9934
# port for the OCSP responder
if ENABLE_OCSP_TEST
OCSP_PORT ?= 9936
OCSP_URI_TEMPLATE = ocsp_uri = http://$(TEST_HOST):$(OCSP_PORT)/ocsp/
endif
# maximum time to wait for MSVA startup (milliseconds)
TEST_SERVICE_MAX_WAIT ?= 10000
# wait loop time for MSVA startup (milliseconds)
TEST_SERVICE_WAIT ?= 400

AM_TESTS_ENVIRONMENT = export APACHE2=@APACHE2@; \
	export AP_LIBEXECDIR=@AP_LIBEXECDIR@; \
	export TEST_LOCK_WAIT="@TEST_LOCK_WAIT@"; \
	export TEST_IP="@TEST_IP@"; \
	export TEST_HOST="@TEST_HOST@"; \
	export TEST_PORT="$(TEST_PORT)"; \
	export MSVA_PORT="$(MSVA_PORT)"; \
	export TEST_SERVICE_MAX_WAIT="$(TEST_SERVICE_MAX_WAIT)"; \
	export TEST_SERVICE_WAIT="$(TEST_SERVICE_WAIT)"; \
	export TEST_QUERY_TIMEOUT="@TEST_QUERY_TIMEOUT@"; \
	export BACKEND_HOST="@TEST_HOST@"; \
	export BACKEND_PORT="$(BACKEND_PORT)"; \
	export HTTP_CLI="@HTTP_CLI@";

if HAVE_SOFTHSM
AM_TESTS_ENVIRONMENT += export SOFTHSM="@SOFTHSM@"; \
	export SOFTHSM_MAJOR_VERSION="@SOFTHSM_MAJOR_VERSION@"; \
	export SOFTHSM_LIB="@SOFTHSM_LIB@"
endif

if ENABLE_OCSP_TEST
AM_TESTS_ENVIRONMENT += export OPENSSL="@OPENSSL@"; \
	export OCSP_PORT="$(OCSP_PORT)";
endif

if ENABLE_NETNS
AM_TESTS_ENVIRONMENT += export UNSHARE="@UNSHARE@"; \
	export USE_TEST_NAMESPACE=1;
endif
# Without flock tests must not run in parallel, and PID files are used
# to prevent conflicts between server instances. Otherwise set lock
# files for flock.
if DISABLE_FLOCK
AM_TESTS_ENVIRONMENT += export TEST_LOCK="apache2.pid"; \
	export BACKEND_LOCK="backend.pid"; \
	export OCSP_LOCK="ocsp.pid";
.NOTPARALLEL:
else
AM_TESTS_ENVIRONMENT += export FLOCK="@FLOCK@"; \
	export TEST_LOCK="$(test_lockfile)"; \
	export BACKEND_LOCK="$(backend_lockfile)"; \
	export OCSP_LOCK="$(ocsp_lockfile)";
endif

# Echo AM_TESTS_ENVIRONMENT. This can be useful for debugging, e.g. if
# you want to manually run an Apache instance with Valgrind using the
# same configuration as a test case.
show-test-env: export TEST_ENV=$(AM_TESTS_ENVIRONMENT)
show-test-env:
	@echo "$${TEST_ENV}"
