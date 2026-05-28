#!/bin/sh

if [ "$1" = 'samba' ] ; then
    exec /usr/sbin/samba -i
else
    exec "$@"
fi
