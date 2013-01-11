
basecrypto_DATA = rsafile dhfile
basecryptodir = ${AP_SYSCONFDIR}

rsafile:
	${GNUTLS_CERTTOOL} --generate-privkey --bits 512 --outfile rsafile
dhfile:
	${GNUTLS_CERTTOOL} --generate-dh-params --bits 1024 --outfile dhfile

clean: clean-am
	rm -f rsafile dhfile
