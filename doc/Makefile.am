EXTRA_DIST = mod_gnutls_manual.mdwn mod_gnutls_manual.yaml.in

if USE_PANDOC
html_DATA = mod_gnutls_manual.html
man5_MANS = mod_gnutls_manual.5
if USE_PDFLATEX
# pandoc && pdflatex
pdf_DATA = mod_gnutls_manual.pdf
endif
else
if USE_MARKDOWN
# !pandoc && markdown
html_DATA = mod_gnutls_manual.html
endif
endif

MOSTLYCLEANFILES = $(html_DATA) $(pdf_DATA) $(man5_MANS)

%.yaml: %.yaml.in
	sed -e s/__MOD_GNUTLS_VERSION__/@MOD_GNUTLS_VERSION@/ < $< > $@

if USE_PANDOC
%.5: %.mdwn %.yaml
	$(PANDOC) --standalone -f markdown -t man -o $@ $^

if USE_PDFLATEX
%.pdf: %.mdwn
	$(PANDOC) --toc -f markdown -o $@ $<
endif
endif

%.html: %.mdwn
if USE_PANDOC
	$(PANDOC) --toc --standalone -f markdown -o $@ $<
else
if USE_MARKDOWN
	$(MARKDOWN) $< > $@
endif
endif
