AC_PREREQ([2.69])
AC_INIT([mod_gnutls],[0.12.1])
OOO_CONFIG_NICE(config.nice)
MOD_GNUTLS_VERSION=AC_PACKAGE_VERSION
AC_CONFIG_SRCDIR([src/mod_gnutls.c])
AC_CONFIG_AUX_DIR(config)

AM_MAINTAINER_MODE([enable])
AC_CANONICAL_TARGET
# mod_gnutls test suite requires GNU make
AM_INIT_AUTOMAKE([-Wno-portability])
AC_CONFIG_HEADERS([include/mod_gnutls_config.h:config.in])

LT_INIT([disable-static])

AC_SUBST(MOD_GNUTLS_VERSION)

AC_PROG_CC
m4_version_prereq([2.70], [:], [AC_PROG_CC_C99])
LT_PATH_LD
AC_PROG_INSTALL
LT_INIT

AC_CONFIG_MACRO_DIR([m4])

AP_VERSION=2.4.17
CHECK_APACHE(,$AP_VERSION,
    :,:,
    AC_MSG_ERROR([*** Apache version $AP_VERSION not found!])
)

PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 3.6.3])
LIBGNUTLS_VERSION=`pkg-config --modversion gnutls`

dnl Maybe use the binaries for tests, too?
AC_ARG_WITH([gnutls-dev],
	AS_HELP_STRING([--with-gnutls-dev=DIR],
		[Use GnuTLS libraries from a development (git) tree. Use \
		this if you want to test mod_gnutls with the latest \
		GnuTLS code.]),
	[
		AS_IF([test -d "${with_gnutls_dev}" ],
		[
			LIBGNUTLS_CFLAGS="-I${with_gnutls_dev}/lib/includes"
			LIBGNUTLS_LIBS="-lgnutls -L${with_gnutls_dev}/lib/.libs -R${with_gnutls_dev}/lib/.libs"
			LIBGNUTLS_VERSION=`PKG_CONFIG_PATH="${with_gnutls_dev}/lib" pkg-config --modversion gnutls`
		],
		[AC_MSG_ERROR([--with-gnutls-dev=DIR requires a directory!])])
	], [])

AC_ARG_ENABLE(vpath-install,
       AS_HELP_STRING([--enable-vpath-install],
               [Modify the Apache module directory provided by apxs to \
	       follow --prefix, if necessary. Most users will not want this, \
	       but it is required for VPATH builds including "make \
	       distcheck".]),
       vpath_install=$enableval, vpath_install=no)
AM_CONDITIONAL([ENABLE_VPATH_INSTALL], [test "$vpath_install" = "yes"])

AC_ARG_ENABLE(clang-coverage,
       AS_HELP_STRING([--enable-clang-coverage],
               [Collect coverage information using clang profiling \
	       instrumentation. Do not use for production!]),
       coverage=$enableval, coverage=no)
COVERAGE_CFLAGS=""
AS_IF([test "${coverage}" != "no"], [
	COVERAGE_CFLAGS="-fprofile-instr-generate -fcoverage-mapping"
])
AM_CONDITIONAL([ENABLE_COVERAGE], [test "$coverage" = "yes"])

AC_ARG_ENABLE(srp,
       AS_HELP_STRING([--enable-srp],
               [enable SRP functionality if supported by libgnutls]),
       use_srp=$enableval, use_srp=no)

# check if the available GnuTLS library supports SRP
AC_SEARCH_LIBS([gnutls_srp_server_get_username], [gnutls], [], [use_srp="no"])

AC_MSG_CHECKING([whether to enable SRP functionality])
AC_MSG_RESULT($use_srp)

GNUTLS_FEAT_CFLAGS=""
AS_IF([test "${use_srp}" != "no"], [
	GNUTLS_FEAT_CFLAGS="-DENABLE_SRP=1"
	AC_MSG_WARN([You have enabled SRP support. This feature is deprecated and will be removed in a future release.])
])

AC_ARG_ENABLE(strict,
       AS_HELP_STRING([--disable-strict],
               [Avoid strict compiler warnings and errors]),
       use_strict=$enableval, use_strict=yes)

STRICT_CFLAGS=""
if test "$use_strict" != "no"; then
	STRICT_CFLAGS="-Wall -Werror -Wextra -Wno-error=deprecated-declarations"
fi

MOD_GNUTLS_DEBUG=0
AC_ARG_ENABLE(gnutls-debug-log,
       AS_HELP_STRING([--enable-gnutls-debug-log],
               [Write GnuTLS debug output to /tmp/gnutls_debug, for \
               debugging only!]),
       enable_gnutls_debug=$enableval, enable_gnutls_debug=no)
if test "$enable_gnutls_debug" != "no"; then
	MOD_GNUTLS_DEBUG=1
fi
AC_SUBST(MOD_GNUTLS_DEBUG)

AM_PATH_PYTHON([3])
AX_PYTHON_MODULE([yaml], [fatal])

dnl Enable testing with Valgrind? Default is "no".
AC_ARG_ENABLE([valgrind-test],
	AS_HELP_STRING([--enable-valgrind-test], [Enable running \
	tests with Valgrind (slow)]),
	[use_valgrind=$enableval], [use_valgrind=no])
AC_MSG_CHECKING([whether to run tests with Valgrind])
AC_MSG_RESULT([$use_valgrind])
AC_PATH_PROG([VALGRIND], [valgrind], [no])
AS_IF([test "${use_valgrind}" != "no" -a "${VALGRIND}" = "no"],
      [AC_MSG_ERROR([Valgrind test are enabled, but "valgrind" not \
      found in PATH!])])
AM_CONDITIONAL([ENABLE_VALGRIND], [test "${use_valgrind}" != "no"])

dnl Optionally disable flock
AC_ARG_ENABLE(flock,
	AS_HELP_STRING([--disable-flock], [Disable use of flock during tests \
	(some exotic architectures don't support it)]),
	[use_flock=$enableval], [use_flock=yes])
# Check if flock is available and supports --timeout
AC_PATH_PROG([FLOCK], [flock], [no])
AS_IF([test "${FLOCK}" != "no"],
      [
	AC_MSG_CHECKING([whether ${FLOCK} supports --timeout])
	lockfile="$(mktemp)"
	AS_IF([${FLOCK} --timeout 1 ${lockfile} true >&AS_MESSAGE_LOG_FD 2>&1],
	      [flock_works="yes"], [flock_works="no"])
	AC_MSG_RESULT([$flock_works])
	# Old versions of flock do not support --verbose. They fail
	# without executing the command but still return 0. Check for
	# this behavior by testing if the rm command was executed.
	AC_MSG_CHECKING([whether ${FLOCK} supports --verbose])
	testfile="$(mktemp)"
	AS_IF([${FLOCK} --verbose --timeout 1 ${lockfile} rm "${testfile}" \
			>&AS_MESSAGE_LOG_FD 2>&1; test ! -e "${testfile}"],
	      [flock_verbose="yes"; FLOCK="${FLOCK} --verbose"],
	      [flock_verbose="no"; rm "${testfile}"])
	AC_MSG_RESULT([$flock_verbose])
	rm "${lockfile}"
      ],
      [flock_works="no"])
# disable flock if requested by user or it doesn't support timeout
AM_CONDITIONAL([DISABLE_FLOCK],
	       [test "$enable_flock" = "no" || test "$flock_works" = "no"])

# openssl is needed as the responder for OCSP tests
AC_PATH_PROG([OPENSSL], [openssl], [no])
AM_CONDITIONAL([ENABLE_OCSP_TEST], [test "${OPENSSL}" != "no"])

dnl Enable test namespaces? Default is "yes".
AC_ARG_ENABLE(test-namespaces,
	AS_HELP_STRING([--disable-test-namespaces], [Disable use of \
	namespaces for tests (limits parallelization)]),
	[use_netns=$enableval], [use_netns=yes])

# Check if "unshare" is available and has permission to create
# network, IPC, and user namespaces
AC_PATH_PROG([UNSHARE], [unshare], [no])
AS_IF([test "${UNSHARE}" != "no"],
      [
	AC_MSG_CHECKING([for permission to use namespaces])
	AS_IF([${UNSHARE} --net --ipc -r /bin/sh -c \
		"ip link set up lo && ip addr show" >&AS_MESSAGE_LOG_FD 2>&1],
	      [unshare_works="yes"], [unshare_works="no"])
	AC_MSG_RESULT([$unshare_works])
      ],
      [unshare_works="no"])
# decide whether to enable network namespaces
AS_IF([test "$enable_test_namespaces" != "no" \
	    && test "$unshare_works" = "yes"],
      [use_netns="yes"], [use_netns="no"])
AM_CONDITIONAL([ENABLE_NETNS], [test "$use_netns" != "no"])

AC_ARG_ENABLE(msva,
       AS_HELP_STRING([--enable-msva],
               [enable Monkeysphere client certificate verification (deprecated)]),
       use_msva=$enableval, use_msva=no)
AM_CONDITIONAL([USE_MSVA], [test "$use_msva" != "no"])

MSVA_CFLAGS=""
AS_IF([test "$use_msva" != "no"], [
	AC_CHECK_HEADERS([msv/msv.h], [],
	                 [AC_MSG_ERROR([*** No libmsv headers found!])])
	AC_SEARCH_LIBS([msv_query_agent], [msv], [],
	                 [AC_MSG_ERROR([*** No libmsv found with msv_query_agent!])])
	MSVA_CFLAGS="-DENABLE_MSVA=1"
])

AC_MSG_CHECKING([whether to enable MSVA functionality])
AC_MSG_RESULT($use_msva)

# Building documentation requires pandoc, which in turn needs pdflatex
# to build PDF output.
build_doc=no
AC_PATH_PROG([PANDOC], [pandoc], [no])
AC_ARG_ENABLE(pdf-doc,
	AS_HELP_STRING([--disable-pdf-doc], [don't build PDF documentation]))
AS_IF([test "$PANDOC" != "no"], [
	AC_PATH_PROG([PDFLATEX], [pdflatex], [no])
	if test "$PDFLATEX" != "no" && test "${enable_pdf_doc}" != "no"; then
		build_doc="html, manual page, pdf"
	else
		build_doc="html, manual page"
	fi
], [
	AC_PATH_PROG([MARKDOWN], [markdown], [no])
	if test "$MARKDOWN" != "no"; then
		build_doc="html stub"
	fi
])
AM_CONDITIONAL([USE_PANDOC], [test "$PANDOC" != "no"])
AM_CONDITIONAL([USE_PDFLATEX], [test "$PANDOC" != "no" && \
			       test "$PDFLATEX" != "no" && \
			       test "${enable_pdf_doc}" != "no"])
AM_CONDITIONAL([USE_MARKDOWN], [test -n "$MARKDOWN" && \
			       test "$MARKDOWN" != "no"])

# Check for Apache binary
AC_PATH_PROGS([APACHE2], [apache2 httpd], [no], [$PATH:/usr/sbin])
AS_IF([test "${APACHE2}" = "no"], [
	AC_MSG_WARN([Neither apache2 nor httpd found in \
		     PATH. Test suite will fail.])
])

AC_PATH_PROGS([HTTP_CLI], [curl], [no])

MODULE_CFLAGS="${LIBGNUTLS_CFLAGS} ${GNUTLS_FEAT_CFLAGS} ${MSVA_CFLAGS} ${APR_CFLAGS} ${AP_INCLUDES} ${APR_INCLUDES} ${APU_INCLUDES} ${STRICT_CFLAGS} ${COVERAGE_CFLAGS}"
MODULE_LIBS="${LIBGNUTLS_LIBS}"

AC_PATH_PROGS([SOFTHSM], [softhsm2-util], [no])
AM_CONDITIONAL([HAVE_SOFTHSM], [test "${SOFTHSM}" != "no"])

AC_SUBST(MODULE_CFLAGS)
AC_SUBST(MODULE_LIBS)

# Adjust Apache configuration for tests: Use pthread mutex and test
# specific PID files if using namespaces. Otherwise defaults are used,
# and the user can override the default mutex type.
AC_ARG_VAR([APACHE_MUTEX], [Override the default mutex for the test \
			   environment. The value is used only when running \
			   without namespace isolation, tests running in \
			   their own namespaces always use "pthread".])
AS_IF([test -n "${APACHE_MUTEX}"],
      [MUTEX_CONF="Mutex ${APACHE_MUTEX} default"],
      [MUTEX_CONF=""])
AS_IF([test "$use_netns" = "yes"],
      [MUTEX_CONF="Mutex pthread default"; PID_AFFIX="-\${TEST_NAME}"],
      [PID_AFFIX=""])
AC_SUBST(MUTEX_CONF)
AC_SUBST(PID_AFFIX)
AM_SUBST_NOTMAKE(MUTEX_CONF)
AM_SUBST_NOTMAKE(PID_AFFIX)

AC_MSG_CHECKING([which loopback addresses are usable])
loopback_ips="$("${PYTHON}" "${srcdir}/test/check_test_ips.py" -q ::1 127.0.0.1)"
AC_MSG_RESULT(${loopback_ips})

# assign default values to TEST_HOST and TEST_IP if necessary
: ${TEST_HOST:="localhost"}
: ${TEST_IP:="${loopback_ips}"}
AC_ARG_VAR([TEST_HOST], [Host name to use for server instances started by \
			"make check", must resolve to addresses in TEST_IP. \
			The default is "localhost".])
AC_ARG_VAR([TEST_IP], [List of IP addresses to use for server instances \
		      started by "make check". The default is \
		      "[::1] 127.0.0.1". Note that IPv6 addresses must be \
		      enclosed in square brackets.])

: ${TEST_LOCK_WAIT:="30"}
: ${TEST_QUERY_TIMEOUT:="30"}
AC_ARG_VAR([TEST_LOCK_WAIT], [Timeout in seconds to acquire locks for \
			     Apache instances in the test suite, or the \
			     previous instance to remove its PID file if \
			     flock is not used. Default is 30.])
AC_ARG_VAR([TEST_QUERY_TIMEOUT], [Timeout in seconds for HTTPS requests \
				 sent using gnutls-cli in the test suite. \
				 Default is 30.])

dnl Allow user to set SoftHSM PKCS #11 module
AC_ARG_VAR([SOFTHSM_LIB], [Absolute path of the SoftHSM PKCS @%:@11 module to \
			  use. By default the test suite will search common \
			  library paths.])

dnl Build list of "Listen" statements for Apache
LISTEN_LIST="@%:@ Listen addresses for the test servers"
for i in ${TEST_IP}; do
	LISTEN_LIST="${LISTEN_LIST}
Listen ${i}:\${TEST_PORT}"
done
# Available extra ports, tests can "Define" variables of the listed
# names in their apache.conf to enable them.
for j in TEST_HTTP_PORT; do
LISTEN_LIST="${LISTEN_LIST}
<IfDefine ${j}>"
for i in ${TEST_IP}; do
	LISTEN_LIST="${LISTEN_LIST}
	Listen ${i}:\${${j}}"
done
LISTEN_LIST="${LISTEN_LIST}
</IfDefine>"
done
AC_SUBST(LISTEN_LIST)
AM_SUBST_NOTMAKE(LISTEN_LIST)

DX_DOXYGEN_FEATURE(ON)
DX_DOT_FEATURE(ON)
DX_HTML_FEATURE(ON)
DX_MAN_FEATURE(OFF)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN([mod_gnutls], [doc/doxygen.conf], [doc/api])

AC_CONFIG_FILES([Makefile src/Makefile test/Makefile test/tests/Makefile \
			doc/Makefile doc/doxygen.conf include/mod_gnutls.h \
			test/proxy_backend.conf test/ocsp_server.conf \
			test/apache-conf/listen.conf \
			test/apache-conf/netns.conf])
AC_OUTPUT

echo "---"
echo "Configuration summary for mod_gnutls:"
echo ""
echo "   * mod_gnutls version:	${MOD_GNUTLS_VERSION}"
echo "   * Apache Modules directory:	${AP_LIBEXECDIR}"
echo "   * GnuTLS Library version:	${LIBGNUTLS_VERSION}"
echo "   * CFLAGS for GnuTLS:		${LIBGNUTLS_CFLAGS}"
echo "   * LDFLAGS for GnuTLS:	${LIBGNUTLS_LIBS}"
echo "   * SRP Authentication:	${use_srp}"
echo "   * MSVA Client Verification:	${use_msva}"
echo "   * Build documentation:	${build_doc}"
echo ""
echo "---"
