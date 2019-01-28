#!/bin/bash
for mod in mod_http2.so mod_proxy_http2.so; do
    if [ ! -r "${AP_LIBEXECDIR}/${mod}" ]; then
	echo "${mod} not found, skipping." 2>&1
	exit 77
    fi
done
${srcdir}/runtests t-34
