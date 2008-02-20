dnl Check for librsvg libraries
dnl CHECK_RSVG(MINIMUM-VERSION, ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND])
AC_DEFUN([CHECK_RSVG],
[dnl

pname=librsvg-2.0

AC_PATH_PROG(PKG_CONFIG, pkg-config, no)

if test x$PKG_CONFIG = xno ; then
  ifelse([$3], , AC_MSG_ERROR([pkg-config not found. pkg-config is required for librsvg]), $3)
fi

AC_MSG_CHECKING(for librsvg - version >= $1)

if $PKG_CONFIG --atleast-version=$1 $pname; then
  RSVG_LDFLAGS=`$PKG_CONFIG $pname --libs-only-L`
  RSVG_LIBS=`$PKG_CONFIG $pname --libs-only-l --libs-only-other`
  RSVG_CFLAGS=`$PKG_CONFIG $pname --cflags`
  RSVG_VERSION=`$PKG_CONFIG $pname --modversion`
  AC_SUBST(RSVG_LDFLAGS)
  AC_SUBST(RSVG_LIBS)
  AC_SUBST(RSVG_CFLAGS)
  AC_SUBST(RSVG_VERSION)
  ifelse([$2], , AC_MSG_RESULT([yes]), $2)
else
  ifelse([$3], , AC_MSG_ERROR([librsvg >=$1 is not installed.]), $3)
fi
])
