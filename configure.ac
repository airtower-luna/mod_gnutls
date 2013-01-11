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

AP_VERSION=2.0.40
CHECK_APACHE(,$AP_VERSION,
    :,:,
    AC_MSG_ERROR([*** Apache version $AP_VERSION not found!])
)

dnl LIBTOOL="`${APR_CONFIG} --apr-libtool`"
dnl AC_SUBST(LIBTOOL)

dnl Depend on 2.10.0 due to safe renegotiation addition.
MIN_TLS_VERSION=2.10.0
AM_PATH_LIBGNUTLS($MIN_TLS_VERSION,,
 	AC_MSG_ERROR([[
***  
*** libgnutls was not found. You may want to get it from
*** http://www.gnutls.org/
***
]]))

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

dnl CHECK_LUA()

have_apr_memcache=0
CHECK_APR_MEMCACHE([have_apr_memcache=1], [have_apr_memcache=0])
AC_SUBST(have_apr_memcache)

MODULE_CFLAGS="${LIBGNUTLS_CFLAGS} ${SRP_CFLAGS} ${APR_MEMCACHE_CFLAGS} ${APXS_CFLAGS} ${AP_INCLUDES} ${APR_INCLUDES} ${APU_INCLUDES}"
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
echo ""
echo "---"
