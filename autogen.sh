#!/bin/sh

if [ -z $AUTORECONF ]; then
	AUTORECONF=autoreconf
fi

#rm -rf autom4te.cache
$AUTORECONF -f -v -i
#touch stamp-h.in

