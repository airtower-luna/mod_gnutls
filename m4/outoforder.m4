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
