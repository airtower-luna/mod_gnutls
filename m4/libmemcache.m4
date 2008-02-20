dnl Check for memcache client libraries
dnl CHECK_MEMCACHE(ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND])
AC_DEFUN([CHECK_MEMCACHE],
[dnl

AC_ARG_WITH(
    memcache,
    [AC_HELP_STRING([--with-memcache=PATH],[Path memcache libraries])],
    mc_path="$withval",
    :)

dnl # Determine memcache lib directory
if test -z $mc_path; then
    test_paths="/usr/lib /usr/local/lib"
else
    test_paths="${mc_path}/lib"
fi

for x in $test_paths ; do
    AC_MSG_CHECKING([for memcache library in ${x}])
    if test -f ${x}/libmemcache.so.1.0; then
        AC_MSG_RESULT([yes])
        save_CFLAGS=$CFLAGS
        save_LDFLAGS=$LDFLAGS
        CFLAGS="$CFLAGS"
        LDFLAGS="-L$x $LDFLAGS"
        AC_CHECK_LIB(memcache, mc_server_add,
            LIBMEMCACHE_LIBS="-L$x -lmemcache")
        CFLAGS=$save_CFLAGS
        LDFLAGS=$save_LDFLAGS
        break
    else
        AC_MSG_RESULT([no])
    fi
done

AC_SUBST(LIBMEMCACHE_LIBS)

if test -z "${LIBMEMCACHE_LIBS}"; then
  AC_MSG_NOTICE([*** memcache library not found.])
  ifelse([$2], , AC_MSG_ERROR([memcache library is required]), $2)
else
  AC_MSG_NOTICE([using '${LIBMEMCACHE_LIBS}' for memcache])
  ifelse([$1], , , $1) 
fi 
])
