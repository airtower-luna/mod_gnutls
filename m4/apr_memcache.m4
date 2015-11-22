dnl Check for memcache client libraries
dnl CHECK_APR_MEMCACHE(ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND])
dnl Sets:
dnl  APR_MEMCACHE_LIBS
dnl  APR_MEMCACHE_CFLAGS
AC_DEFUN([CHECK_APR_MEMCACHE],
[dnl

AC_ARG_WITH(
	[apu-config],
	[AC_HELP_STRING([--with-apu-config=PATH],[Path to APR Utility Library config tool (apu-1-config)])],
	[apr_util_config="$withval"],
	[])

AC_LIBTOOL_SYS_DYNAMIC_LINKER

save_CFLAGS=$CFLAGS
save_LDFLAGS=$LDFLAGS

dnl # If path to apu-1-config hasn't been set explicitly, try to find it
if test -z "$apr_util_config"; then
	AC_PATH_PROGS([APR_UTIL_CONF], [apu-1-config], [no], [$PATH:/usr/sbin])
else
	AC_MSG_NOTICE([using apu-1-config path set by user: $apr_util_config])
	APR_UTIL_CONF="$apr_util_config"
fi

CFLAGS="`$APR_UTIL_CONF --includes` $CFLAGS"
LDFLAGS="`$APR_UTIL_CONF --link-ld` $LDFLAGS"

AC_CHECK_LIB(
	aprutil-1,
	apr_memcache_create,
	[
		APR_MEMCACHE_LIBS="`$APR_UTIL_CONF --link-ld`"
		APR_MEMCACHE_CFLAGS="`$APR_UTIL_CONF --includes`"
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
