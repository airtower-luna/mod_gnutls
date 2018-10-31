EXTRA_DIST = mod_gnutls_manual.mdwn

if USE_PANDOC
html_DATA = mod_gnutls_manual.html
man3_MANS = mod_gnutls_manual.man
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

MOSTLYCLEANFILES = $(html_DATA) $(pdf_DATA) $(man3_MANS)

if USE_PANDOC
%.man: %.mdwn
	$(PANDOC) --standalone --variable section=3 -f markdown -t man -o $@ $<

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
