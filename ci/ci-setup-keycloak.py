#!/usr/bin/env python
# coding: utf-8
# https://github.com/marcospereirampj/python-keycloak
from argparse import ArgumentParser
import json
from keycloak import KeycloakAdmin
import sys

parser = ArgumentParser()
parser.add_argument(
    "--keycloak-url", default="https://keycloak.dev.k8tre.internal", help="Keycloak URL"
)
parser.add_argument(
    "--jupyterhub-url",
    default="https://jupyter.dev.k8tre.internal",
    help="JupyterHub URL",
)
parser.add_argument("--keycloak-admin", default="admin", help="Keycloak admin user")
parser.add_argument(
    "--keycloak-password", default="admin", help="Keycloak admin password"
)
parser.add_argument(
    "--user", default="example@example.com", help="Username of new user"
)
parser.add_argument("--password", default="secret", help="Password for new user")
parser.add_argument("--firstname", default="Example", help="First name of new user")
parser.add_argument("--lastname", default="User", help="Last name of new user")
parser.add_argument(
    "--client-name", default="jupyterhub", help="JupyterHub OAuth client name"
)
parser.add_argument(
    "--client-secret",
    default="jupyterhub-client-secret",
    help="JupyterHub OAuth client secret",
)
parser.add_argument(
    "--admin-role",
    default="jupyterhub-admins",
    help="Name of JupyterHub Keycloak admin role",
)
parser.add_argument(
    "--user-role",
    default="jupyterhub-users",
    help="Name of JupyterHub Keycloak user role",
)
parser.add_argument(
    "--scope-name",
    default="jupyterhub-roles",
    help="Custom scope name to use for JupyterHub Keycloak roles",
)
parser.add_argument(
    "--verify",
    default="true",
    help="Set to the path to a CA, or 'false' to disable SSL verification, default is to use system CA",
)


args = parser.parse_args()


def output(firstline, message=None):
    if sys.stdout.isatty():
        # Bold green text
        print(f"\033[1m\033[32m{firstline}\033[97m\033[0m")
    else:
        print(firstline)
    if message is not None:
        print(json.dumps(message, indent=2))


jupyterhub_url = args.jupyterhub_url

verify = args.verify
if verify.lower() == "true":
    verify = True
if verify.lower() == "false":
    verify = False

keycloak_admin = KeycloakAdmin(
    server_url=args.keycloak_url,
    username=args.keycloak_admin,
    password=args.keycloak_password,
    realm_name="master",
    verify=verify,
)

# Create a user
user_payload = {
    "email": args.user,
    "username": args.user,
    "enabled": True,
    "firstName": args.firstname,
    "lastName": args.lastname,
    "credentials": [
        {
            "value": args.password,
            "type": "password",
        }
    ],
}
uid = keycloak_admin.get_user_id(args.user)
if uid:
    output(f"Updating user {args.user} ({uid})", user_payload)
    keycloak_admin.update_user(uid, user_payload)
else:
    output(f"Creating user {args.user}", user_payload)
    keycloak_admin.create_user(user_payload)

# Create an OAuth client for JupyterHub
client_payload = {
    "clientId": args.client_name,
    "name": args.client_name,
    "rootUrl": args.jupyterhub_url.rstrip("/"),
    "baseUrl": "/",
    "redirectUris": ["/hub/oauth_callback"],
    "clientAuthenticatorType": "client-secret",
    "secret": args.client_secret,
}
cid = keycloak_admin.get_client_id(args.client_name)
if cid:
    output(f"Updating client {args.client_name} ({cid})", client_payload)
    keycloak_admin.update_client(cid, client_payload)
else:
    output(f"Creating client {args.client_name}", client_payload)
    cid = keycloak_admin.create_client(client_payload)
# print(keycloak_admin.get_client(cid))

# Create some client specific roles (you could also create realm roles that can be used by multiple clients)
client_role_admins_payload = {
    "name": args.admin_role,
    "description": "JupyterHub admins",
}
output(f"Creating/updating client role {args.admin_role}", client_role_admins_payload)
keycloak_admin.create_client_role(cid, client_role_admins_payload, skip_exists=True)
client_role_users_payload = {
    "name": args.user_role,
    "description": "JupyterHub users",
}
output(f"Creating/updating client role {args.user_role}", client_role_users_payload)
keycloak_admin.create_client_role(cid, client_role_users_payload, skip_exists=True)

# Create or update a custom scope called "jupyterhub-groups" that maps Keycloak client Roles
scope = {
    "name": args.scope_name,
    "description": "JupyterHub Keycloak roles",
    "protocol": "openid-connect",
    "protocolMappers": [
        {
            "name": args.scope_name,
            "protocol": "openid-connect",
            # Map client roles:
            "protocolMapper": "oidc-usermodel-client-role-mapper",
            # Map realm roles:
            # "protocolMapper": "oidc-usermodel-realm-role-mapper",
            # Map Keycloak groups:
            # "protocolMapper": "oidc-group-membership-mapper",
            "config": {
                "multivalued": "true",
                # Include in the userinfo response
                "userinfo.token.claim": "true",
                # The userinfo field
                "claim.name": "jupyterhub.roles",
                "jsonType.label": "String",
                # Only return client scopes for jupyterhub
                "usermodel.clientRoleMapping.clientId": args.client_name,
            },
        }
    ],
}
output(f"Creating or updating scope {args.scope_name}", scope)
scope_id = keycloak_admin.create_client_scope(scope, skip_exists=True)
keycloak_admin.update_client_scope(scope_id, scope)

# Add scope to client
keycloak_admin.add_client_optional_client_scope(cid, scope_id, {})

# Assign users to client roles
client_admin_role = keycloak_admin.get_client_role(cid, args.admin_role)
client_user_role = keycloak_admin.get_client_role(cid, args.user_role)

admin_uid = keycloak_admin.get_user_id(args.keycloak_admin)
output(
    f"Assigning roles to admin {args.keycloak_admin} ({admin_uid})",
    [client_admin_role, client_user_role],
)
keycloak_admin.assign_client_role(admin_uid, cid, [client_admin_role, client_user_role])

user_uid = keycloak_admin.get_user_id(args.user)
output(f"Assigning roles to user {args.user} ({user_uid})", client_user_role)
keycloak_admin.assign_client_role(user_uid, cid, [client_user_role])
