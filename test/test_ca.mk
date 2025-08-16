#!/usr/bin/make -f
# Authors:
# Daniel Kahn Gillmor <dkg@fifthhorseman.net>
# Fiona Klute <fiona.klute@gmx.de>

# General rules to set up a miniature CA & server & client environment
# for the test suite

%/template: $(srcdir)/%/template.in
	@mkdir -m 0700 -p $(@D)
	sed s/__HOSTNAME__/$(TEST_HOST)/ < $< > $@
	sed -i -e "s,__OCSP_URI__,$(OCSP_URI_TEMPLATE)$(dir $(*))," $@
	for i in $(patsubst [%],%,$(TEST_IP)); do \
		IP_ADDRS="$${IP_ADDRS}\nip_address = $${i}"; \
	done; \
	sed -i -e "s,__IP_ADDRESSES__,$${IP_ADDRS#\\n}," $@

%/uid: $(srcdir)/%/uid.in
	@mkdir -m 0700 -p $(@D)
	sed s/__HOSTNAME__/$(TEST_HOST)/ < $< > $@

%/secret.key:
	@mkdir -m 0700 -p $(@D)
	certtool --outfile $@ --generate-privkey

.PRECIOUS: %/secret.key

%/secret.pgp.raw: %/uid %/secret.key
	PEM2OPENPGP_USAGE_FLAGS=authenticate,certify,sign pem2openpgp "$$(cat $<)" < $(dir $@)secret.key > $@

%/secret.pgp: %/secret.pgp.raw pgpcrc
	(printf -- '-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: test\n\n' && \
	base64 < $< && \
	printf -- '=' && \
	./pgpcrc < $< | base64 && \
	printf -- '-----END PGP PRIVATE KEY BLOCK-----\n' ) > $@

%/gpg.conf: %/secret.pgp
	rm -f $(dir $@)pubring.gpg $(dir $@)secring.gpg $(dir $@)trustdb.gpg $(dir $@)pubring.kbx $(dir $@)private-keys-v1.d/*.key
	GNUPGHOME=$(dir $@) gpg --import $<
	printf "%s:6:\n" "$$(GNUPGHOME=$(dir $@) gpg --with-colons --list-secret-keys --fingerprint | grep ^fpr: | cut -f 10 -d :)" | GNUPGHOME=$(dir $@) gpg --import-ownertrust
	printf "default-key %s\n" "$$(GNUPGHOME=$(dir $@) gpg --with-colons --list-secret-keys --fingerprint | grep ^fpr: | cut -f 10 -d :)" > $@

%/minimal.pgp: %/gpg.conf
	if test -r $@; then rm $@; fi
	GNUPGHOME=$(dir $@) gpg --output $@ --armor --export "$$(GNUPGHOME=$(dir $@) gpg --with-colons --list-secret-keys --fingerprint | grep ^fpr: | cut -f 10 -d :)"

# Import and signing modify the shared keyring, which leads to race
# conditions with parallel make. Locking avoids this problem. Building
# authority/minimal.pgp (instead of just authority/gpg.conf) before
# */cert.pgp avoids having to lock for all */minimal.pgp, too.
%/cert.pgp: %/minimal.pgp authority/minimal.pgp
	if test -r $@; then rm $@; fi
	GNUPGHOME=authority/ $(GPG_FLOCK) gpg --import $<
	GNUPGHOME=authority/ $(GPG_FLOCK) gpg --batch --sign-key --no-tty --yes "$$(GNUPGHOME=$(dir $@) gpg --with-colons --list-secret-keys --fingerprint | grep ^fpr: | cut -f 10 -d :)"
	GNUPGHOME=authority/ $(GPG_FLOCK) gpg --output $@ --armor --export "$$(GNUPGHOME=$(dir $@) gpg --with-colons --list-secret-keys --fingerprint | grep ^fpr: | cut -f 10 -d :)"

# special rule for root CAs
root_cert_rule = certtool --outfile $@ --generate-self-signed --load-privkey $(dir $@)secret.key --template $<
root_chain_rule = cp $< $@
authority/x509.pem rogueca/x509.pem: %/x509.pem: %/template %/secret.key
	$(root_cert_rule)
authority/x509-chain.pem rogueca/x509-chain.pem: %/x509-chain.pem: %/x509.pem
	$(root_chain_rule)

# generic rule for building non-root certificates, with the CA in the
# parent directory
cert_rule = certtool --outfile $@ --generate-certificate --load-ca-certificate $(dir $@)../x509.pem --load-ca-privkey $(dir $@)../secret.key --load-privkey $(dir $@)secret.key --template $<
chain_rule = cat $< $(dir $@)../x509-chain.pem > $@

# certificates signed by the test root CA
%/x509.pem: %/template %/secret.key authority/secret.key authority/x509.pem
	$(cert_rule)
%/x509-chain.pem: %/x509.pem authority/x509-chain.pem
	$(chain_rule)

# certificates signed by the test sub CA
authority/subca/%/x509.pem: authority/subca/%/template authority/subca/%/secret.key authority/subca/x509.pem
	$(cert_rule)
authority/subca/%/x509-chain.pem: authority/subca/%/x509.pem authority/subca/x509-chain.pem
	$(chain_rule)

# certificates signed by rogue CA (for error cases)
rogueca/%/x509.pem: rogueca/%/template rogueca/%/secret.key rogueca/x509.pem
	$(cert_rule)

%/softhsm2.db: %/x509.pem %/secret.key
	SOFTHSM="$(SOFTHSM)" \
	$(PYTHON) $(srcdir)/softhsm-init.py --token-dir $@ --privkey $(dir $@)secret.key --certificate $(dir $@)x509.pem

# Generate CRL revoking a certain certificate. Currently used to
# revoke the server certificate and check if setting the CRL as
# GnuTLSProxyCRLFile causes the connection to the back end server to
# fail.
%/crl.pem: %/x509.pem $(srcdir)/%/crl.template
	certtool --generate-crl \
		--outfile $@ \
		--load-ca-privkey authority/secret.key \
		--load-ca-certificate authority/x509.pem \
		--load-certificate $< \
		--template "$(srcdir)/$(*)/crl.template"

# The "find" command builds a list of all certificates directly below
# the CA that aren't for the ocsp-responder.
%/ocsp_index.txt: $(x509_tokens) gen_ocsp_index
	./gen_ocsp_index $$(find $(*) -mindepth 2 -maxdepth 2 ! -path '*/ocsp-responder/*' -name x509.pem) > $@

%/ocsp_index.txt.attr:
	@mkdir -m 0700 -p $(dir $@)
	echo "unique_subject = no" > $@
