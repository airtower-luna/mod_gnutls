AC_INIT
OOO_CONFIG_NICE(config.nice)
AC_CONFIG_SRCDIR([src/mod_gnutls.c])
AM_MAINTAINER_MODE
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE(mod_gnutls, 0.1.0)
AM_CONFIG_HEADER([include/mod_gnutls_config.h:config.in])


AC_PROG_CC
AC_PROG_LD
AC_PROG_INSTALL
AM_PROG_LIBTOOL


AP_VERSION=2.0.40
CHECK_APACHE(,$AP_VERSION,
    :,:,
    AC_MSG_ERROR([*** Apache version $AP_VERSION not found!])
)

MIN_TLS_VERSION=1.1.0
CHECK_LIBGNUTLS($MIN_TLS_VERSION)

MODULE_CFLAGS="${LIBGNUTLS_CFLAGS} ${APXS_CFLAGS} ${AP_INCLUDES} ${APR_INCLUDES} ${APU_INCLUDES}"
MODULE_LIBS="${LIBGNUTLS_LIBS}"

AC_SUBST(MODULE_CFLAGS)
AC_SUBST(MODULE_LIBS)

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

echo "---"
echo "Configuration summary for mod_gnutls"
echo ""
echo "   * Apache Modules directory:	${AP_LIBEXECDIR}"
echo "   * GnuTLS Library Version:	${LIBGNUTLS_VERSION}"
echo ""
echo "---"
