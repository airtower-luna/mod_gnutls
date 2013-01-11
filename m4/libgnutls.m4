dnl Check for libgnutls libraries
dnl CHECK_LIBGNUTLS(MINIMUM-VERSION)
AC_DEFUN([CHECK_LIBGNUTLS],
[dnl

AC_ARG_WITH(
    libgnutls,
    [AC_HELP_STRING([--with-libgnutls=PATH],[Path to libgnutls])],
    tls_prefix="$withval",
    tls_prefix="/usr"
    )

    if test -x $tls_prefix -a ! -d $tls_prefix; then
        GTLS_BIN=$tls_prefix
    else
        test_paths="$tls_prefix:$tls_prefix/bin:$tls_prefix/sbin"
        test_paths="${test_paths}:/usr/bin:/usr/sbin"
        test_paths="${test_paths}:/usr/local/bin:/usr/local/sbin"
        AC_PATH_PROG(GTLS_BIN, libgnutls-config, no, [$test_paths])
    fi

    if test "$GTLS_BIN" = "no"; then
        AC_MSG_ERROR([*** The libgnutls-config binary installed by GnuTLS could not be found!])
        AC_MSG_ERROR([*** Use the --with-libgnutls option with the full path to libgnutls-config])
    else
        dnl TODO: Check versions
        LIBGNUTLS_LIBS="`$GTLS_BIN --libs`"
        LIBGNUTLS_CFLAGS="`$GTLS_BIN --cflags`"
        LIBGNUTLS_VERSION="`$GTLS_BIN --version`"
        LIBGNUTLS_PREFIX="`$GTLS_BIN --prefix`"
        GNUTLS_CERTTOOL="${LIBGNUTLS_PREFIX}/bin/certtool"        
        AC_SUBST(LIBGNUTLS_LIBS)
        AC_SUBST(LIBGNUTLS_CFLAGS)
        AC_SUBST(LIBGNUTLS_VERSION)
        AC_SUBST(GNUTLS_CERTTOOL)
        AC_SUBST(LIBGNUTLS_PREFIX)
    fi
])
