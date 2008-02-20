dnl Check for apreq2 libraries
dnl CHECK_APREQ2(MINIMUM-VERSION, ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND])
AC_DEFUN([CHECK_APREQ2],
[dnl

AC_ARG_WITH(
    apreq2,
    [AC_HELP_STRING([--with-apreq2=PATH],[Path to your apreq2-config])],
    ap_path="$withval",
    ap_path="/usr"
    )

    if test -x $ap_path -a ! -d $ap_path; then
        AP_BIN=$ap_path
    else
        test_paths="$ap_path:$ap_path/bin:$ap_path/sbin"

	dnl Search the Apache Binary Directories too. Since we should set these in apache.m4
	if test -d $AP_BINDIR; then
            test_paths="${test_paths}:${AP_BINDIR}"
	fi
	if test -d $AP_SBINDIR; then
            test_paths="${test_paths}:${AP_SBINDIR}"
	fi

        test_paths="${test_paths}:/usr/bin:/usr/sbin"
        test_paths="${test_paths}:/usr/local/bin:/usr/local/sbin"
        AC_PATH_PROG(AP_BIN, apreq2-config, no, [$test_paths])
    fi

    if test "$AP_BIN" = "no"; then
        AC_MSG_ERROR([*** The apreq2-config  binary installed by apreq2 could not be found!])
        AC_MSG_ERROR([*** Use the --with-apreq2 option with the full path to apreq2-config])
        ifelse([$3], , AC_MSG_ERROR([apreq2 >=$1 is not installed.]), $3)
    else
        dnl TODO: Do a apreq2-config  Version check here...
        APREQ_LIBS="`$AP_BIN --link-ld --ldflags --libs  2>/dev/null`"
        APREQ_CFLAGS="`$AP_BIN  --includes   2>/dev/null`"
        AC_SUBST(APREQ_LIBS)
        AC_SUBST(APREQ_CFLAGS)
        ifelse([$2], , AC_MSG_RESULT([yes]), $2)
    fi
])
