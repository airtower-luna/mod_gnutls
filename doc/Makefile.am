EXTRA_DIST = mod_gnutls_manual.mdwn

if USE_PANDOC
html_DATA = mod_gnutls_manual.html
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

MOSTLYCLEANFILES = $(html_DATA) $(pdf_DATA)

# pdf_DATA will be empty if pandoc isn't available
$(html_DATA) $(pdf_DATA): mod_gnutls_manual.mdwn
if USE_PANDOC
	$(PANDOC) --toc --standalone -f markdown -o $@ $<
else
if USE_MARKDOWN
	$(MARKDOWN) $< > $@
endif
endif
