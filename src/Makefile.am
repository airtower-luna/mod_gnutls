# installation directory for Apache modules
if ENABLE_VPATH_INSTALL
apmodpkglibdir = $(subst ${AP_EXEC_PREFIX},${prefix},${AP_LIBEXECDIR})
else
apmodpkglibdir = ${AP_LIBEXECDIR}
endif

mod_gnutls_la_SOURCES = mod_gnutls.c gnutls_io.c gnutls_cache.c \
	gnutls_config.c gnutls_hooks.c gnutls_ocsp.c gnutls_proxy.c \
	gnutls_sni.c gnutls_util.c gnutls_watchdog.c
mod_gnutls_la_CFLAGS = -Wall ${MODULE_CFLAGS}
mod_gnutls_la_LDFLAGS = -module -avoid-version ${MODULE_LIBS}
noinst_HEADERS = gnutls_cache.h gnutls_config.h gnutls_ocsp.h \
	gnutls_proxy.h gnutls_sni.h gnutls_util.h gnutls_watchdog.h

apmodpkglib_LTLIBRARIES = mod_gnutls.la
