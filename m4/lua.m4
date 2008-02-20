dnl Check for Lua 5.0 Libraries
dnl CHECK_LUA(ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND])
dnl Sets:
dnl  LUA_CFLAGS
dnl  LUA_LIBS
AC_DEFUN([CHECK_LUA],
[dnl

AC_ARG_WITH(
    lua,
    [AC_HELP_STRING([--with-lua=PATH],[Path to the Lua 5.0 prefix])],
    lua_path="$withval",
    :)

dnl # Determine memcache lib directory
if test -z $mc_path; then
    test_paths="/usr/local /usr"
else
    test_paths="${lua_path}"
fi

for x in $test_paths ; do
    AC_MSG_CHECKING([for lua.h in ${x}/include/lua50])
    if test -f ${x}/include/lua50/lua.h; then
        AC_MSG_RESULT([yes])
        save_CFLAGS=$CFLAGS
        save_LDFLAGS=$LDFLAGS
        CFLAGS="$CFLAGS"
        LDFLAGS="-L$x/lib $LDFLAGS"
        AC_CHECK_LIB(lua50, lua_open,
            [
            LUA_LIBS="-L$x/lib -llua50 -llualib50"
            LUA_CFLAGS="-I$x/include/lua50"
            ])
        CFLAGS=$save_CFLAGS
        LDFLAGS=$save_LDFLAGS
        break
    else
        AC_MSG_RESULT([no])
    fi
    AC_MSG_CHECKING([for lua.h in ${x}/include])
    if test -f ${x}/include/lua.h; then
        AC_MSG_RESULT([yes])
        save_CFLAGS=$CFLAGS
        save_LDFLAGS=$LDFLAGS
        CFLAGS="$CFLAGS"
        LDFLAGS="-L$x/lib $LDFLAGS"
        AC_CHECK_LIB(lua, lua_open,
            [
            LUA_LIBS="-L$x/lib -llua -llualib"
            LUA_CFLAGS="-I$x/include/lua50"
            ])
        CFLAGS=$save_CFLAGS
        LDFLAGS=$save_LDFLAGS
        break
    else
        AC_MSG_RESULT([no])
    fi
done

AC_SUBST(LUA_LIBS)
AC_SUBST(LUA_CFLAGS)

if test -z "${LUA_LIBS}"; then
  AC_MSG_NOTICE([*** Lua 5.0 library not found.])
  ifelse([$2], , AC_MSG_ERROR([Lua 5.0 library is required]), $2)
else
  AC_MSG_NOTICE([using '${LUA_LIBS}' for Lua Library])
  ifelse([$1], , , $1) 
fi 
])
