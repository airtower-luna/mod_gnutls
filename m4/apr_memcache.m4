dnl Check for memcache client libraries
dnl CHECK_APR_MEMCACHE(ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND])
dnl Sets:
dnl  APR_MEMCACHE_LIBS
AC_DEFUN([CHECK_APR_MEMCACHE],
[dnl

AC_ARG_WITH(
    apr-memcache-prefix,
    [AC_HELP_STRING([--with-apr-memcache-prefix=PATH],[Install prefix for apr_memcache])],
    apr_memcache_prefix="$withval",
    apr_memcache_prefix="/usr",
    :)
AC_ARG_WITH(
    apr-memcache-libs,
    [AC_HELP_STRING([--with-apr-memcache-libs=PATH],[Path to apr_memcache libs])],
    apr_memcache_libs="$withval",
    apr_memcache_libs="$apr_memcache_prefix/lib"
    :)
AC_ARG_WITH(
    apr-memcache-includes,
    [AC_HELP_STRING([--with-apr-memcache-includes=PATH],[Path to apr_memcache includes])],
    apr_memcache_includes="$withval",
    apr_memcache_includes="$apr_memcache_prefix/include/apr_memcache-0"
    :)


AC_LIBTOOL_SYS_DYNAMIC_LINKER

dnl # Determine memcache lib directory
save_CFLAGS=$CFLAGS
save_LDFLAGS=$LDFLAGS
CFLAGS="-I$apr_memcache_includes $APR_INCLUDES $CFLAGS"
LDFLAGS="-L$apr_memcache_libs $LDFLAGS"
AC_CHECK_LIB(
    apr_memcache,
    apr_memcache_create,
    [
	APR_MEMCACHE_LIBS="-R$apr_memcache_libs -L$apr_memcache_libs -lapr_memcache"
	APR_MEMCACHE_CFLAGS="-I$apr_memcache_includes"
    ]
)
CFLAGS=$save_CFLAGS
LDFLAGS=$save_LDFLAGS

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
