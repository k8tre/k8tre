#!/bin/sh

set -e

realm="ad.${DOMAIN}"
REALM=$(echo "$realm" | tr '[:lower:]' '[:upper:]')

if [ ! -f /samba/etc/smb.conf ] ; then
    mkdir -p /samba/etc /samba/lib /samba/logs
    samba-tool domain provision \
	       --domain=AD \
	       --realm="$REALM" \
	       --server-role=dc \
	       --dns-backend=SAMBA_INTERNAL || \
	rm -rf /samba/*
fi
