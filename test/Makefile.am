SUBDIRS = tests

VALGRIND_SUPPRESS = suppressions.valgrind
EXTRA_DIST = $(VALGRIND_SUPPRESS)

if ENABLE_VALGRIND
valgrind = --valgrind \
	$(foreach supp,$(VALGRIND_SUPPRESS),--valgrind-suppressions "$(srcdir)/$(supp)")
else
valgrind =
endif

# Generate the test scripts
test-%.bash: test-template.bash.in | tests/%/
	testname="$(*)"; \
	sed -e s/_NUM_/$${testname%%_*}/ -e 's,_VALGRIND_,$(valgrind),' < $< > $@
	chmod a+x $@

test_scripts = test-00_basic.bash \
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
test_scripts += test-15_basic_msva.bash
endif
test_scripts += test-16_view-status.bash \
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
	test-30_ip_based_vhosts.bash \
	test-31_vhost_SNI_serveralias_match.bash \
	test-32_vhost_SNI_serveralias_mismatch.bash \
	test-33_vhost_SNI_serveralias_missinghost.bash \
	test-34_TLS_reverse_proxy_h2.bash \
	test-35_client_reauth.bash \
	test-36_OCSP_server_nonce.bash

MOSTLYCLEANFILES = $(test_scripts)
dist_check_SCRIPTS = netns_py.bash test-template.bash.in

TEST_EXTENSIONS = .bash .py
PY_LOG_COMPILER = $(PYTHON)
TESTS = doctest-mgstest.py $(test_scripts)

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

# Python tools for tests
noinst_PYTHON = https-test-client.py mgstest/http.py mgstest/__init__.py \
	mgstest/hooks.py mgstest/services.py mgstest/softhsm.py \
	mgstest/tests.py mgstest/valgrind.py runtest.py softhsm-init.py \
	doctest-mgstest.py required-modules.py data/ocsp.py

# Identities in the miniature CA, server, and client environment for
# the test suite
shared_identities = authority authority/client
pgp_identities = $(shared_identities)
x509_only_identities = authority/server authority/imposter \
	authority/subca authority/subca/server \
	rogueca rogueca/rogueclient
if ENABLE_OCSP_TEST
x509_only_identities += authority/ocsp-responder authority/subca/ocsp-responder
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
tokens = $(x509_tokens)
if USE_MSVA
tokens += $(pgp_tokens)
endif

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
check_DATA = $(tokens) authority/server/crl.pem

MOSTLYCLEANFILES += cache/* logs/* outputs/* authority/server/crl.pem

cert_templates = authority/template.in authority/client/template.in \
	authority/imposter/template.in authority/ocsp-responder/template \
	authority/server/template.in \
	authority/subca/template.in authority/subca/server/template.in \
	authority/subca/ocsp-responder/template \
	rogueca/template rogueca/rogueclient/template.in
generated_templates = authority/template authority/client/template \
	authority/imposter/template rogueca/rogueclient/template \
	authority/server/template

# Delete X.509 private keys on full clean. Note that unless you need
# to generate fresh keys, the "mostlyclean" target should be
# sufficient (see below).
CLEANFILES = $(x509_keys)

# Delete X.509 certificates and generated templates on "mostlyclean"
# target. Certificates can be rebuilt without generating new key
# pairs, and regenerating them makes it possible to change identities
# (e.g. host names) without wasting time on new keys (which would
# happen after "clean").
MOSTLYCLEANFILES += $(x509_certs) $(generated_templates) $(identities:=/uid)


# Delete PGP keyrings on "mostlyclean" target. They are created from
# the X.509 private keys and certificates with an expiration time of
# one day, so regenerating them is both fast and frequently
# necessary.
pgp_patterns = /*.pgp /*.pgp.raw /*.gpg /*.gpg~ /gpg.conf \
	/*.kbx /*.kbx~ /S.gpg-agent /private-keys-v1.d/*
MOSTLYCLEANFILES += $(foreach pat,$(pgp_patterns),$(pgp_identities:=$(pat))) \
	authority/lock authority/tofu.db
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
check_DATA += $(msva_home)/trustdb.gpg authority/client/uid
MOSTLYCLEANFILES += $(foreach pat,$(pgp_patterns),$(msva_home)$(pat))
$(msva_home)/trustdb.gpg: authority/minimal.pgp authority/client/cert.pgp
	mkdir -p -m 0700 $(dir $@)
	GNUPGHOME=$(dir $@) gpg --import < $<
	printf "%s:6:\n" "$$(GNUPGHOME=authority/ gpg --with-colons --list-secret-keys --fingerprint | grep ^fpr: | cut -f 10 -d :)" | GNUPGHOME=$(dir $@) gpg --import-ownertrust
	GNUPGHOME=$(dir $@) gpg --import < authority/client/cert.pgp
	printf "keyserver does-not-exist.example\n" > $(msva_home)/gpg.conf
endif

if ENABLE_OCSP_TEST
# rules to build OCSP database
ocsp_index_data = authority/ocsp_index.txt authority/ocsp_index.txt.attr \
	authority/subca/ocsp_index.txt authority/subca/ocsp_index.txt.attr
check_DATA += $(ocsp_index_data)
MOSTLYCLEANFILES += $(ocsp_index_data)

# The "find" command builds a list of all certificates directly below
# the CA that aren't for the ocsp-responder.
%/ocsp_index.txt: $(x509_tokens) gen_ocsp_index
	./gen_ocsp_index $$(find $(*) -mindepth 2 -maxdepth 2 ! -path '*/ocsp-responder/*' -name x509.pem) > $@

%/ocsp_index.txt.attr:
	@mkdir -m 0700 -p $(dir $@)
	echo "unique_subject = no" > $@

# Build certificate chain files. Note that intermediate tokens must be
# listed explicitly, or the dependency chain will be broken because
# the higher level pattern matches, too.
chain_tokens = authority/server/x509-chain.pem \
	authority/subca/x509-chain.pem \
	authority/subca/server/x509-chain.pem
check_DATA += $(chain_tokens)
MOSTLYCLEANFILES += $(chain_tokens) authority/x509-chain.pem
endif

# SoftHSM token, note that the SoftHSM 2 token is a directory
SOFTHSM2_TOKEN = authority/server/softhsm2.db
# included in mostlyclean-local below
clean-softhsm2-db:
	-rm -rf $(SOFTHSM2_TOKEN)

if HAVE_SOFTHSM
check_DATA += $(SOFTHSM2_TOKEN)
endif HAVE_SOFTHSM

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
apache_data = base_apache.conf cgi_module.conf data/dump.cgi \
	data/test.txt data/secret/mirror.cgi data/secret/test.txt \
	mime.types proxy_mods.conf

# Which modules are compiled into the Apache binary varies between
# distributions. required-modules.py creates additional LoadModule
# directives if needed.
check_DATA += apache-conf/required-modules.conf
MOSTLYCLEANFILES += apache-conf/required-modules.conf
apache-conf/required-modules.conf: required-modules.py
	APACHE2=@APACHE2@ AP_LIBEXECDIR=@AP_LIBEXECDIR@ $(PYTHON) $< >$@

# Documentation for the test system
test_doc = README.md sample_fail.yml sample_test.yml

EXTRA_DIST += $(apache_data) $(cert_templates) $(shared_identities:=/uid.in) \
	authority/server/crl.template $(test_doc)

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
# port for plain HTTP server
TEST_HTTP_PORT ?= 9935
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
	export PYTHON="@PYTHON@"; \
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
	export TEST_HTTP_PORT="$(TEST_HTTP_PORT)"; \
	export HTTP_CLI="@HTTP_CLI@";

if HAVE_SOFTHSM
AM_TESTS_ENVIRONMENT += export SOFTHSM="@SOFTHSM@"; \
	export SOFTHSM_LIB="@SOFTHSM_LIB@";
endif

if ENABLE_OCSP_TEST
AM_TESTS_ENVIRONMENT += export OPENSSL="@OPENSSL@"; \
	export OCSP_PORT="$(OCSP_PORT)";
endif

if ENABLE_VALGRIND
AM_TESTS_ENVIRONMENT += export VALGRIND="@VALGRIND@";
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

# Build the test suite README as HTML if pandoc is available.
if USE_PANDOC
noinst_DATA = README.html
MOSTLYCLEANFILES += $(noinst_DATA)
%.html: %.md $(srcdir)/../doc/style.css
	$(PANDOC) --css $(filter %.css,$^) --metadata pagetitle="$(<)" --self-contained -f markdown -o $@ $<
endif
