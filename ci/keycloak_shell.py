""" 
This script is used to interact with the Keycloak admin API.
It can be used to list users, create users, create groups, add users to groups, reset passwords, and delete users.
It can also be used to create realms, clients, client scopes, and client roles.
"""
# These are the environment variables that can be used 
#to configure the Keycloak admin API.
# export KC_URL="http://localhost:8081"       
# export KC_ADMIN="user"                     
# export KC_REALM="karectl-app
# export KC_PASSWORD="your-admin-password" 

import cmd
import os
import sys

from keycloak import KeycloakAdmin


class KeycloakShell(cmd.Cmd):
    """ Interactive shell to interact with Keycloak admin API.
    """
    intro = "\nWelcome to the Keycloak admin shell.\nType help or ? to list commands.\n"
    prompt = "kcadmin> "

    def __init__(self, server_url, admin, password, realm):
        """ Initialize the KeycloakShell class.
        """
        super().__init__()
        self.keycloak_admin = KeycloakAdmin(
            server_url=server_url,
            username=admin,
            password=password,
            realm_name=realm,
            verify=False,
        )

    def do_list_users(self, arg):
        """ List all users from the realm.
        """
        user_list = self.keycloak_admin.get_users()
        for user in user_list:
            print(f"- {user['username']} ({user.get('email', '')})")

    def do_add_user(self, arg):
        """ Create a new user.
            
            Usage: add_user username password
            
            Args:
                arg (str): username and password separated by a space.
        """
        args = arg.split()
        if len(args) < 2:
            print("Usage: add_user username password")
            return

        username, password = args[0], args[1]
        payload = {
            "username": username,
            "enabled": True,
            "credentials": [{
                "type": "password",
                "value": password,
                "temporary": False
            }],
        }
        if not self.keycloak_admin.get_user_id(username):
            self.keycloak_admin.create_user(payload)
            print(f"Created user {username}")
        else:
            print(f"User {username} already exists")

    def do_add_group(self, arg):
        """ Create a new group in the realm.
            
            Usage: add_group groupname
            
            Args:
                arg (str): groupname
        """
        if not arg:
            print("Usage: add_group groupname")
            return

        if not any(group["name"] == arg for group in self.keycloak_admin.get_groups()):
            self.keycloak_admin.create_group({"name": arg})
            print(f"Created group {arg}")
        else:
            print(f"Group {arg} already exists")

    def do_add_to_group(self, arg):
        """ Add a user to a group.
            
            Usage: add_user_to_group username groupname
            
            Args:
                arg (str): username and groupname separated by a space.
        """
        args = arg.split()
        if len(args) < 2:
            print("Usage: add_user_to_group username groupname")
            return

        username, groupname = args[0], args[1]
        uid = self.keycloak_admin.get_user_id(username)

        target_id = None
        for group in self.keycloak_admin.get_groups():
            if group["name"] == groupname:
                target_id = group["id"]
        if uid and target_id:
            self.keycloak_admin.group_user_add(uid, target_id)
            print(f"Added {username} to {groupname}")
        else:
            print("User or group not found.")

    def do_list_groups(self, arg):
        """ List all groups in the realm.
        """
        for group in self.keycloak_admin.get_groups():
            print(f"- {group['name']}")

    def do_reset_password(self, arg):
        """ Reset the password for a user.
            
            Usage: reset_password username newpassword
            
            Args:
                arg (str): username and newpassword separated by a space.
        """
        args = arg.split()
        if len(args) < 2:
            print("Usage: reset_password username newpassword")
            return

        username, new_password = args[0], args[1]
        uid = self.keycloak_admin.get_user_id(username)
        if not uid:
            print(f"User {username} does not exist")
            return
        self.keycloak_admin.set_user_password(uid, new_password, temporary=False)
        print(f"Password reset for user {username}")

    def do_delete_user(self, arg):
        """ Delete a user from the realm.
            
            Usage: delete_user username
            
            Args:
                arg (str): username
        """
        if not arg:
            print("Usage: delete_user username")
            return

        username = arg.strip()
        uid = self.keycloak_admin.get_user_id(username)
        if uid:
            self.keycloak_admin.delete_user(uid)
            print(f"Deleted user {username}")
        else:
            print(f"User {username} does not exist")

    def do_exit(self, arg):
        """ Exit the shell.
        """
        self.close()
        return True

    def close(self):
        """ Close the Keycloak admin connection.
        """
        try:
            if hasattr(self, 'keycloak_admin') and self.keycloak_admin:
                self.keycloak_admin.connection = None
        except:
            pass


if __name__ == "__main__":
    # Use environment variables for config, or hardcode for your environment
    url = os.environ.get("KC_URL", "http://localhost:8080")
    admin = os.environ.get("KC_ADMIN", "admin")
    pw = os.environ.get("KC_PASSWORD", "admin")
    realm = os.environ.get("KC_REALM", "karectl-app")
    shell = KeycloakShell(url, admin, pw, realm)
   
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        shell.close()
