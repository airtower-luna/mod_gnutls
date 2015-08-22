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
    :)
AC_ARG_WITH(
    apr-memcache-libs,
    [AC_HELP_STRING([--with-apr-memcache-libs=PATH],[Path to apr_memcache libs])],
    apr_memcache_libs="$withval",
    :)
AC_ARG_WITH(
    apr-memcache-includes,
    [AC_HELP_STRING([--with-apr-memcache-includes=PATH],[Path to apr_memcache includes])],
    apr_memcache_includes="$withval",
    :)


AC_LIBTOOL_SYS_DYNAMIC_LINKER

dnl # Determine memcache lib directory
save_CFLAGS=$CFLAGS
save_LDFLAGS=$LDFLAGS

if test -n "$apr_memcache_libs"; then
    apr_memcache_libdir=$apr_memcache_libs
elif test -n "$apr_memcache_prefix"; then
    apr_memcache_libdir=$apr_memcache_prefix/lib
fi
if test -n "$apr_memcache_libdir"; then
    LDFLAGS="-L$apr_memcache_libdir $LDFLAGS"
fi

if test -n "$apr_memcache_includes"; then
    apr_memcache_includedir=$apr_memcache_includes
elif test -n "$apr_memcache_prefix"; then
    apr_memcache_includedir=$apr_memcache_prefix/include/apr_memcache-0
else
    apr_memcache_includedir=$includedir/apr_memcache-0
fi

CFLAGS="-I$apr_memcache_includedir $CFLAGS"


AC_CHECK_LIB(
    apr_memcache,
    apr_memcache_create,
    [
	APR_MEMCACHE_LIBS="-lapr_memcache"
	if test -n "$apr_memcache_libdir"; then
	    APR_MEMCACHE_LIBS="-R$apr_memcache_libdir -L$apr_memcache_libdir $APR_MEMCACHE_LIBS"
	fi
	APR_MEMCACHE_CFLAGS="-I$apr_memcache_includedir"
    ]
)


dnl # if the apr_memcache was not found, try apr-util
if test -z "${APR_MEMCACHE_LIBS}"; then
    if test -n "$apr_memcache_includes"; then
	apr_memcache_includedir=$apr_memcache_includes
    elif test -n "$apr_memcache_prefix"; then
	apr_memcache_includedir=$apr_memcache_prefix/include/aprutil-1
    else
	apr_memcache_includedir=$includedir/aprutil-1
    fi
    AC_CHECK_LIB(
	aprutil-1,
	apr_memcache_create,
	[
	    APR_MEMCACHE_LIBS="`apu-1-config --link-ld`"
	    APR_MEMCACHE_CFLAGS="`apu-1-config --includes`"
	]
    )
fi


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
