#!/bin/sh

if [ -z $ACLOCAL ]; then
	ACLOCAL=aclocal
fi
if [ -z $AUTOCONF ]; then 
	AUTOCONF=autoconf
fi
if [ -z $AUTOHEADER ]; then
	AUTOHEADER=autoheader
fi
if [ -z $AUTORECONF ]; then
	AUTORECONF=autoreconf
fi

#rm -rf autom4te.cache
$AUTORECONF -f -i
#touch stamp-h.in

for x in providers/*; do
	if [ -e $x/autogen.sh ]; then
		echo Generating Config files in $x
		(cd $x; ./autogen.sh $*)
	fi
done
