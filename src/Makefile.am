CLEANFILES = .libs/libmod_gnutls *~

libmod_gnutls_la_SOURCES = mod_gnutls.c
libmod_gnutls_la_CFLAGS = -Wall ${MODULE_CFLAGS}
libmod_gnutls_la_LDFLAGS = ${MODULE_LIBS}

lib_LTLIBRARIES = libmod_gnutls.la

make_so: $(lib_LTLIBRARIES)
	@if test ! -L mod_gnutls.so ; then ln -s .libs/libmod_gnutls.so mod_gnutls.so ; fi

clean:
	rm -f mod_gnutls.so
	rm -f *.o *.lo *.la 
	rm -fr .libs

install: make_so
	@${APXS_BIN} -i -n svn_view mod_gnutls.so
	@echo ""
	@echo ""
	@echo "***********************************************"
	@echo ""
	@echo "   Please read the documentation at            "
	@echo "   http://www.outoforder.cc/ for   "
	@echo "   details on configuration of this module     "
	@echo ""
	@echo "***********************************************"
	@echo ""

activate: make_so
	@${APXS_BIN} -i -a -n svn_view mod_gnutls.so
	@echo ""
	@echo ""
	@echo "***********************************************"
	@echo ""
	@echo "   Please read the documentation at            "
	@echo "   http://www.outoforder.cc/ for   "
	@echo "   details on configuration of this module     "
	@echo ""
	@echo "***********************************************"
	@echo ""
