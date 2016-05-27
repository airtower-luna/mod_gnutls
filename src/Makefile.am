# installation directory for Apache modules
apmodpkglibdir = ${AP_LIBEXECDIR}

mod_gnutls_la_SOURCES = mod_gnutls.c gnutls_io.c gnutls_cache.c gnutls_config.c gnutls_hooks.c
mod_gnutls_la_CFLAGS = -Wall ${MODULE_CFLAGS}
mod_gnutls_la_LDFLAGS = -module -avoid-version ${MODULE_LIBS}

apmodpkglib_LTLIBRARIES = mod_gnutls.la
