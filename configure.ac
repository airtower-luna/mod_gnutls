dnl 
AC_INIT(mod_gnutls, 0.5.10)
OOO_CONFIG_NICE(config.nice)
MOD_GNUTLS_VERSION=AC_PACKAGE_VERSION
AC_PREREQ(2.53)
AC_CONFIG_SRCDIR([src/mod_gnutls.c])
AC_CONFIG_AUX_DIR(config)

OOO_MAINTAIN_MODE
AM_MAINTAINER_MODE
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE(AC_PACKAGE_NAME, AC_PACKAGE_VERSION)
AM_CONFIG_HEADER(include/mod_gnutls_config.h:config.in)

AC_SUBST(MOD_GNUTLS_VERSION)

AC_PROG_CC
AC_PROG_LD
AC_PROG_INSTALL
AC_PROG_LIBTOOL

AC_CONFIG_MACRO_DIR([m4])

AP_VERSION=2.0.40
CHECK_APACHE(,$AP_VERSION,
    :,:,
    AC_MSG_ERROR([*** Apache version $AP_VERSION not found!])
)

PKG_CHECK_MODULES(LIBGNUTLS, [gnutls >= 2.12.6])

LIBGNUTLS_VERSION=`pkg-config --modversion gnutls`

AC_ARG_ENABLE(srp,
       AS_HELP_STRING([--disable-srp],
               [unconditionally disable the SRP functionality]),
       use_srp=$enableval, use_srp=yes)

SRP_CFLAGS=""
if test "$use_srp" != "no"; then
 	SRP_CFLAGS="-DENABLE_SRP=1"
fi

AC_MSG_CHECKING([whether to enable SRP functionality])
AC_MSG_RESULT($use_srp)

AC_ARG_ENABLE(msva,
       AS_HELP_STRING([--enable-msva],
               [enable Monkeysphere client certificate verification]),
       use_msva=$enableval, use_msva=no)

MSVA_CFLAGS=""
if test "$use_msva" != "no"; then
 	AC_CHECK_HEADERS([msv/msv.h], [], 
                         [AC_MSG_ERROR([*** No libmsv headers found!])])
        AC_SEARCH_LIBS([msv_query_agent], [msv], [],
                         [AC_MSG_ERROR([*** No libmsv found with msv_query_agent!])])
 	MSVA_CFLAGS="-DENABLE_MSVA=1"
fi

AC_MSG_CHECKING([whether to enable MSVA functionality])
AC_MSG_RESULT($use_msva)

have_apr_memcache=0
CHECK_APR_MEMCACHE([have_apr_memcache=1], [have_apr_memcache=0])
AC_SUBST(have_apr_memcache)

MODULE_CFLAGS="${LIBGNUTLS_CFLAGS} ${SRP_CFLAGS} ${MSVA_CFLAGS} ${APR_MEMCACHE_CFLAGS} ${APXS_CFLAGS} ${AP_INCLUDES} ${APR_INCLUDES} ${APU_INCLUDES}"
MODULE_LIBS="${APR_MEMCACHE_LIBS} ${LIBGNUTLS_LIBS}"

AC_SUBST(MODULE_CFLAGS)
AC_SUBST(MODULE_LIBS)

AC_CONFIG_FILES([Makefile src/Makefile include/mod_gnutls.h])
AC_OUTPUT

echo "---"
echo "Configuration summary for mod_gnutls:"
echo ""
echo "   * mod_gnutls version:	${MOD_GNUTLS_VERSION}"
echo "   * Apache Modules directory:	${AP_LIBEXECDIR}"
echo "   * GnuTLS Library version:	${LIBGNUTLS_VERSION}"
echo "   * SRP Authentication:          ${use_srp}"
echo "   * MSVA Client Verification:    ${use_msva}"
echo ""
echo "---"
