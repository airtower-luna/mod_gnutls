dnl 
AC_INIT(mod_gnutls, 0.7.2)
OOO_CONFIG_NICE(config.nice)
MOD_GNUTLS_VERSION=AC_PACKAGE_VERSION
AC_PREREQ(2.53)
AC_CONFIG_SRCDIR([src/mod_gnutls.c])
AC_CONFIG_AUX_DIR(config)

OOO_MAINTAIN_MODE
AM_MAINTAINER_MODE
AC_CANONICAL_TARGET
# mod_gnutls test suite requires GNU make
AM_INIT_AUTOMAKE([-Wno-portability])
AM_CONFIG_HEADER(include/mod_gnutls_config.h:config.in)

AC_SUBST(MOD_GNUTLS_VERSION)

AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_LD
AC_PROG_INSTALL
AC_PROG_LIBTOOL

AC_CONFIG_MACRO_DIR([m4])

AP_VERSION=2.2.0
CHECK_APACHE(,$AP_VERSION,
    :,:,
    AC_MSG_ERROR([*** Apache version $AP_VERSION not found!])
)

PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 3.1.4])

LIBGNUTLS_VERSION=`pkg-config --modversion gnutls`

AC_ARG_ENABLE(srp,
       AS_HELP_STRING([--disable-srp],
               [unconditionally disable the SRP functionality]),
       use_srp=$enableval, use_srp=yes)

# check if the available GnuTLS library supports SRP
AC_SEARCH_LIBS([gnutls_srp_server_get_username], [gnutls], [], [use_srp="no"])

SRP_CFLAGS=""
if test "$use_srp" != "no"; then
	SRP_CFLAGS="-DENABLE_SRP=1"
fi

AC_ARG_ENABLE(strict,
       AS_HELP_STRING([--disable-strict],
               [Avoid strict compiler warnings and errors]),
       use_strict=$enableval, use_strict=yes)

STRICT_CFLAGS=""
if test "$use_strict" != "no"; then
        STRICT_CFLAGS="-Wall -Werror -Wextra"
fi

AC_MSG_CHECKING([whether to enable SRP functionality])
AC_MSG_RESULT($use_srp)

dnl Optionally disable flock
AC_ARG_ENABLE(flock,
	AS_HELP_STRING([--disable-flock], [Disable use of flock during tests \
	(some exotic architectures don't support it)]),
	[use_flock=$enableval], [use_flock=yes])
dnl If flock is not disabled, make sure it's available
if test "$enable_flock" != "no"; then
	AC_PATH_PROG([FLOCK], [flock], [no])
	use_flock=${FLOCK}
fi
AM_CONDITIONAL([DISABLE_FLOCK], [test "$enable_flock" = "no"])

dnl Enable test namespaces? Default is "yes".
AC_ARG_ENABLE(test-namespaces,
	AS_HELP_STRING([--disable-test-namespaces], [Disable use of network \
	namespaces to run tests in parallel (some architectures might not \
	support it)]),
	[use_netns=$enableval], [use_netns=yes])
dnl If namespaces are enabled, make sure "unshare" is available
if test "$enable_test_namespaces" != "no"; then
	AC_PATH_PROG([UNSHARE], [unshare], [no])
	use_netns=${UNSHARE}
	# default mutex breaks in namespace, use "pthread" instead
	MUTEX_TYPE="pthread"
	PID_AFFIX="-\${TEST_NAME}"
else
	MUTEX_TYPE="default"
	PID_AFFIX=""
fi
AM_CONDITIONAL([ENABLE_NETNS], [test "$use_netns" != "no"])
AC_SUBST(MUTEX_TYPE)
AC_SUBST(PID_AFFIX)
AM_SUBST_NOTMAKE(MUTEX_TYPE)
AM_SUBST_NOTMAKE(PID_AFFIX)

AC_ARG_ENABLE(msva,
       AS_HELP_STRING([--enable-msva],
               [enable Monkeysphere client certificate verification]),
       use_msva=$enableval, use_msva=no)
AM_CONDITIONAL([USE_MSVA], [test "$use_msva" != "no"])

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

# Building documentation requires pandoc, which in turn needs pdflatex
# to build PDF output.
build_doc=no
AC_PATH_PROG([PANDOC], [pandoc], [no])
if test "$PANDOC" != "no"; then
	AC_PATH_PROG([PDFLATEX], [pdflatex], [no])
	if test "$PDFLATEX" != "no"; then
		build_doc=yes
	else
		build_doc="html only"
	fi
else
	AC_PATH_PROG([MARKDOWN], [markdown], [no])
	if test "$MARKDOWN" != "no"; then
		build_doc="html stub"
	fi
fi
AM_CONDITIONAL([USE_PANDOC], [test "$PANDOC" != "no"])
AM_CONDITIONAL([USE_PDFLATEX], [test "$PANDOC" != "no" && \
			       test "$PDFLATEX" != "no"])
AM_CONDITIONAL([USE_MARKDOWN], [test -n "$MARKDOWN" && \
			       test "$MARKDOWN" != "no"])

# Check for Apache binary
AC_PATH_PROGS([APACHE2], [apache2 httpd], [no], [$PATH:/usr/sbin])
if test "${APACHE2}" = "no"; then
	AC_MSG_WARN([Neither apache2 nor httpd found in \
		     PATH. Test suite will fail.])
fi

MODULE_CFLAGS="${LIBGNUTLS_CFLAGS} ${SRP_CFLAGS} ${MSVA_CFLAGS} ${APR_MEMCACHE_CFLAGS} ${APXS_CFLAGS} ${AP_INCLUDES} ${APR_INCLUDES} ${APU_INCLUDES} ${STRICT_CFLAGS}"
MODULE_LIBS="${APR_MEMCACHE_LIBS} ${LIBGNUTLS_LIBS}"

AC_SUBST(MODULE_CFLAGS)
AC_SUBST(MODULE_LIBS)

# assign default values to TEST_HOST and TEST_IP if necessary
: ${TEST_HOST:="localhost"}
: ${TEST_IP:="[[::1]] 127.0.0.1"}
AC_ARG_VAR([TEST_HOST], [Host name to use for server instances started by \
			"make check", must resolve to addresses in TEST_IP. \
			The default is "localhost".])
AC_ARG_VAR([TEST_IP], [List of IP addresses to use for server instances \
		      started by "make check". The default is \
		      "[::1] 127.0.0.1". Note that IPv6 addresses must be \
		      enclosed in square brackets.])
AM_SUBST_NOTMAKE(TEST_IP)

dnl Build list of "Listen" statements for Apache
LISTEN_LIST="# Listen addresses for the test servers"
for i in ${TEST_IP}; do
	LISTEN_LIST="${LISTEN_LIST}
Listen ${i}:\${TEST_PORT}"
done
AC_SUBST(LISTEN_LIST)
AM_SUBST_NOTMAKE(LISTEN_LIST)

AC_CONFIG_FILES([Makefile src/Makefile test/Makefile test/tests/Makefile \
			  doc/Makefile include/mod_gnutls.h test/listen.conf \
			  test/apache-conf/netns.conf])
AC_OUTPUT

echo "---"
echo "Configuration summary for mod_gnutls:"
echo ""
echo "   * mod_gnutls version:	${MOD_GNUTLS_VERSION}"
echo "   * Apache Modules directory:	${AP_LIBEXECDIR}"
echo "   * GnuTLS Library version:	${LIBGNUTLS_VERSION}"
echo "   * SRP Authentication:	${use_srp}"
echo "   * MSVA Client Verification:	${use_msva}"
echo "   * Build documentation:	${build_doc}"
echo ""
echo "---"
