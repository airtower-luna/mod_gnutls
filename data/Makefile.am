
basecrypto_DATA = rsafile dhfile
basecryptodir = ${AP_SYSCONFDIR}

rsafile:
	${GNUTLS_CERTTOOL} --generate-privkey --bits 512 --outfile rsafile --quick-random
dhfile:
	${GNUTLS_CERTTOOL} --generate-dh-params --bits 1024 --outfile dhfile --quick-random

clean: clean-am
	rm -f rsafile dhfile
