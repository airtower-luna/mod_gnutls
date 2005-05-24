#!/bin/sh
m4/buildconf.py \
  --libtoolize  \
  --aclocal     \
  --automake    \
  --autoconf    \
  --autoheader

rm -rf autom4te.cache
