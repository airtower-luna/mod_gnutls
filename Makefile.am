AUTOMAKE_OPTIONS = foreign dist-bzip2 no-dist-gzip

EXTRA_DIST = m4/outoforder.m4 m4/apache.m4 \
		m4/apr_memcache.m4 \
		m4/apache_test.m4  \
		include/mod_gnutls.h.in \
		README CHANGELOG \
		NOTICE LICENSE

AM_DISTCHECK_CONFIGURE_FLAGS = "--enable-vpath-install"
DISTCLEANFILES = config.nice
MOSTLYCLEANFILES = $(DX_CLEANFILES)

SUBDIRS = src test doc
ACLOCAL_AMFLAGS = -I m4

@DX_RULES@
