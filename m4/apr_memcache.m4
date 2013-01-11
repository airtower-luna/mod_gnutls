dnl Check for memcache client libraries
dnl CHECK_APR_MEMCACHE(ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND])
dnl Sets:
dnl  APR_MEMCACHE_LIBS
AC_DEFUN([CHECK_APR_MEMCACHE],
[dnl

AC_ARG_WITH(
    apr-memcache,
    [AC_HELP_STRING([--with-apr-memcache=PATH],[Path to apr_memcache prefix])],
    mc_path="$withval",
    :)

AC_LIBTOOL_SYS_DYNAMIC_LINKER

dnl # Determine memcache lib directory
if test -z $mc_path; then
    test_paths="/usr/local /usr /usr/local/apache2"
else
    test_paths="${mc_path}"
fi

if test -n ${AP_PREFIX}; then
    test_paths="${AP_PREFIX} ${test_paths}"
fi

for x in $test_paths ; do
    amc_shlib="${x}/libapr_memcache${shrext_cmds}"
    AC_MSG_CHECKING([for apr_memcache library in ${x}/lib])
    if test -f ${amc_shlib}; then
        AC_MSG_RESULT([yes])
        save_CFLAGS=$CFLAGS
        save_LDFLAGS=$LDFLAGS
        CFLAGS="$CFLAGS"
        LDFLAGS="-L$x/lib $LDFLAGS"
        AC_CHECK_LIB(apr_memcache, apr_memcache_create,
            [
            APR_MEMCACHE_LIBS="-R$x/lib -L$x/lib -lapr_memcache"
            APR_MEMCACHE_CFLAGS="-I$x/include/apr_memcache-0"
            ])
        CFLAGS=$save_CFLAGS
        LDFLAGS=$save_LDFLAGS
        break
    else
        AC_MSG_RESULT([no])
    fi
done

AC_SUBST(APR_MEMCACHE_LIBS)
AC_SUBST(APR_MEMCACHE_CFLAGS)

if test -z "${APR_MEMCACHE_LIBS}"; then
  AC_MSG_NOTICE([*** memcache library not found.])
  ifelse([$2], , AC_MSG_ERROR([memcache library is required]), $2)
else
  AC_MSG_NOTICE([using '${APR_MEMCACHE_LIBS}' for memcache])
  ifelse([$1], , , $1) 
fi 
])
