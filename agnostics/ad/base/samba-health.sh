#!/bin/sh
set -e

export KRB5_CONFIG=/krb5.conf

realm="ad.${DOMAIN}"
REALM=$(echo "$realm" | tr '[:lower:]' '[:upper:]')

kdestroy -c /tmp/ccache
kinit -k -t /Administrator.keytab Administrator@$REALM -c /tmp/ccache
