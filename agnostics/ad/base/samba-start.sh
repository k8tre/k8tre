#!/bin/sh

set -e

realm="ad.${DOMAIN}"
REALM=$(echo "$realm" | tr '[:lower:]' '[:upper:]')

sleep 5

######################################################################
# Create management account credentials and put them in a configmap
password=$(tr -dc 'A-Za-z0-9!?%=' < /dev/urandom | head -c 10)
samba-tool user setpassword Administrator --newpassword "$password@"
ktutil <<CMD
addent -password -p Administrator@$REALM -k 1 -e aes256-cts-hmac-sha1-96
$password@
wkt Administrator.keytab
CMD

cp /samba/lib/private/krb5.conf /krb5.conf
sed -i '/default_domain =/aadmin_server = 127.0.0.1\nkdc = 127.0.0.1' /krb5.conf
sed -i '/dns_lookup_kdc/s/true/false/' /krb5.conf
cat /krb5.conf
export KRB5_CONFIG=/krb5.conf
export KRB5CCNAME=/ccache
kinit -k -t /Administrator.keytab "Administrator@$REALM"
kubectl -n ad create configmap administrator.keytab --from-file Administrator.keytab \
	-o yaml --dry-run=client | kubectl apply -f -


######################################################################
# Check for an rDNS zone and create it if not
echo "Ensuring we have an rDNS zone"
(samba-tool dns zonelist dc0 --use-krb5-ccache=/ccache | grep "in-addr\.arpa") || (
    # Usage: samba-tool dns zonecreate <server> <zone> [options]
    # Usage: samba-tool dns add <server> <zone> <name> <A|AAAA|PTR|CNAME|NS|MX|SRV|TXT> <data>
    samba-tool dns zonecreate dc0 10.in-addr.arpa --use-krb5-ccache=/ccache
)

######################################################################
# Ensure our own record is up to date
echo "Checking dc0 DNS"
MYIP=$(ip a | grep -A1 link/ether | grep inet | awk '{ print $2 }' | awk -F'/' '{ print $1 }')
nslookup dc0.$REALM 127.0.0.1 | grep -A1 Name: | grep Address | awk '{ print $2 }' | grep -v "$MYIP" | \
    while read ip ; do
	echo "Replacing $ip with $MYIP"
	# We love unnamed arguments!
	# Usage: samba-tool dns update <server> <zone> <name> <A|AAAA|PTR|CNAME|NS|MX|SOA|SRV|TXT> <olddata> <newdata>
	samba-tool dns update dc0 $REALM dc0 A $ip $MYIP --use-krb5-ccache=/ccache || true

	# Remove old rDNS records
	rip=$(echo "$ip" | awk -F. '{ print $4"."$3"."$2 }')
	samba-tool dns delete dc0 10.in-addr.arpa $rip PTR dc0.$REALM. --use-krb5-ccache=/ccache || true
    done

nslookup $REALM 127.0.0.1 | grep -A1 Name: | grep Address | awk '{ print $2 }' | grep -v "$MYIP" | \
    while read ip ; do
	samba-tool dns delete dc0 $REALM '.' a $ip --use-krb5-ccache=/ccache || true
    done

samba-tool dns add dc0 $REALM '.' a $MYIP --use-krb5-ccache=/ccache || true

MYRIP=$(echo $MYIP | awk -F. '{ print $4"."$3"."$2 }')
samba-tool dns add dc0 10.in-addr.arpa $MYRIP PTR dc0.$REALM --use-krb5-ccache=/ccache
