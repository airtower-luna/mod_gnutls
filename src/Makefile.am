# installation directory for Apache modules
if ENABLE_VPATH_INSTALL
apmodpkglibdir = $(subst ${AP_EXEC_PREFIX},${prefix},${AP_LIBEXECDIR})
else
apmodpkglibdir = ${AP_LIBEXECDIR}
endif

mod_gnutls_la_SOURCES = mod_gnutls.c gnutls_io.c gnutls_cache.c \
	gnutls_config.c gnutls_hooks.c gnutls_ocsp.c
mod_gnutls_la_CFLAGS = -Wall ${MODULE_CFLAGS}
mod_gnutls_la_LDFLAGS = -module -avoid-version ${MODULE_LIBS}
noinst_HEADERS = gnutls_ocsp.h

apmodpkglib_LTLIBRARIES = mod_gnutls.la
