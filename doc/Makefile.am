EXTRA_DIST = mod_gnutls_manual.mdwn

if USE_PANDOC
html_DATA = mod_gnutls_manual.html
endif
# pandoc needs pdflatex for PDF output, so USE_PDFLATEX will only be
# enabled if USE_PANDOC is, too.
if USE_PDFLATEX
pdf_DATA = mod_gnutls_manual.pdf
endif
MOSTLYCLEANFILES = $(html_DATA) $(pdf_DATA)

$(html_DATA) $(pdf_DATA): mod_gnutls_manual.mdwn
	$(PANDOC) --toc --standalone -f markdown -o $@ $<
