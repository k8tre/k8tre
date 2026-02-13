#!/bin/sh

set -e

KRB5CCNAME="/Administrator.ccache"
realm="ad.${DOMAIN}"
REALM=$(echo "${realm}" | tr '[:lower:]' '[:upper:]')
SAMBA_OPTS="-H ldaps://dc0.$realm -U Administrator@$REALM --use-kerberos=required --use-krb5-ccache=$KRB5CCNAME"
LDB_OPTS="-H ldap://dc0.$realm --use-kerberos=required --use-krb5-ccache=$KRB5CCNAME"

date
echo "Updating Kerberos keytab ConfigMaps"
echo "    SAMBA_OPTS: $SAMBA_OPTS"
echo "    REALM: $REALM"

mkdir /samba/etc
cat > /etc/samba/smb.conf <<CONF
    [global]
        tls verify peer = no_check
CONF

    cat > /config <<CONF
    [libdefaults]
    default_realm = $REALM
    kdc_timesync = 1
    ccache_type = 4
    forwardable = true
    proxiable = true
    dns_lookup_kdc = false
    dns_lookup_realm = false

        [realms]
    $REALM = {
      kdc = DC0.$REALM
    }

    [domain_realm]
    .$REALM = $REALM
    .$realm = $REALM
    ad = $REALM
    AD = $REALM
    .ad = $REALM
    .AD = $REALM
CONF

kubectl -n ad create configmap "krb5.conf" --from-file /config -o yaml --dry-run=client | kubectl apply -f -
cp /config /etc/krb5.conf

kinit -k -t /Administrator.keytab -c Administrator.ccache "Administrator@$REALM"

current_users=$(samba-tool user list $SAMBA_OPTS)
current_groups=$(samba-tool group list $SAMBA_OPTS)

# CRDs for this are a bit messy.
#
# `group.identity.k8tre.io` has two valid schemas
# depending on whether it's a subgroup or not. In the
# case of subgroup, it defines project as a list, when
# it should probably be limited to a single project.
#
# We can filter out the ones we want by checking for
# .spec.members
kubectl  -n keycloak get group -o yaml | yq -r '.items[] | select(.spec.members) | .spec | (.projects[0])' | sort -u > /tmp/projects.txt
while read project <&3 ; do
    # Create a user group in AD if it doesn't exist already.
    (echo "$current_groups" | grep "^project-$project$" >/dev/null) || (
        samba-tool group add "project-$project" $SAMBA_OPTS
    )
	kubectl -n "project-$project" create configmap "krb5.conf" --from-file /config -o yaml --dry-run=client | kubectl apply -f -
done 3< /tmp/projects.txt
rm /tmp/projects.txt


function gen_user_keytab() {
    username="$1"
    password=$(tr -dc 'A-Za-z0-9!?%=' < /dev/urandom | head -c 32)
    samba-tool user setpassword "$username" --newpassword "$password" $SAMBA_OPTS

    # Create a keytab for this user principal.
    (
        echo "clear"
        echo "addent -password -p $username@$REALM -k 1 -e aes256-cts-hmac-sha1-96"
        echo "$password"
        echo "wkt /keytab"
    ) | ktutil

    current_kvno=$(ldbsearch $LDB_OPTS "samAccountName=$username" msDS-KeyVersionNumber | grep ^msDS-KeyVersionNumber | awk '{ print $2 }')    
    kubectl -n "project-$project" create configmap "$username.keytab" --from-file /keytab --from-literal "kvno=$current_kvno" -o yaml --dry-run=client | kubectl apply -f -

    rm /keytab
}

# Handle the creation of new users
kubectl  -n keycloak get group -o yaml | yq -r '.items[] | select(.spec.members) | .spec | (.members[] + "-" + .projects[0] + "\t" + .projects[0])' > /tmp/usernames.txt
while read username project <&3 ; do
    # Create user if they don't exist
    (echo "$current_users" | grep "^$username$" >/dev/null) || (
        samba-tool user add "$username" --random-password $SAMBA_OPTS
        samba-tool group addmembers "project-$project" "$username" $SAMBA_OPTS
        gen_user_keytab "$username"
        continue
    )

    # Verify kvno
    current_kvno=$(ldbsearch $LDB_OPTS "samAccountName=$username" msDS-KeyVersionNumber | grep ^msDS-KeyVersionNumber | awk '{ print $2 }')
    exported_kvno=$(kubectl -n "project-$project" get configmap "$username.keytab" -o yaml -o=jsonpath='{.data.kvno}' || echo 0)
    echo "$username - Current KVNO: $current_kvno, Exported KVNO: $exported_kvno"

    if [ "$current_kvno" != "$exported_kvno" ] ; then
        echo "Updating $username.keytab"
        gen_user_keytab "$username"
    fi
done 3< /tmp/usernames.txt

exit 0
