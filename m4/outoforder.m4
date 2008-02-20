dnl m4 for utility macros used by all out of order projects

dnl this writes a "config.nice" file which reinvokes ./configure with all
dnl of the arguments. this is different from config.status which simply
dnl regenerates the output files. config.nice is useful after you rebuild
dnl ./configure (via autoconf or autogen.sh)
AC_DEFUN([OOO_CONFIG_NICE],[
  echo configure: creating $1
  rm -f $1
  cat >$1<<EOF
#! /bin/sh
#
# Created by configure

EOF

  for arg in [$]0 "[$]@"; do
    if test "[$]arg" != "--no-create" -a "[$]arg" != "--no-recursion"; then
        echo "\"[$]arg\" \\" >> $1
    fi
  done
  echo '"[$]@"' >> $1
  chmod +x $1
])

dnl this macro adds a maintainer mode option to enable programmer specific
dnl  code in makefiles
AC_DEFUN([OOO_MAINTAIN_MODE],[
  AC_ARG_ENABLE(
        maintainer,
        [AC_HELP_STRING([--enable-maintainer],[Enable maintainer mode for this project])],
        AC_MSG_RESULT([Enabling Maintainer Mode!!])
        OOO_MAINTAIN=1,
        OOO_MAINTAIN=0)
  AC_SUBST(OOO_MAINTAIN)
])
