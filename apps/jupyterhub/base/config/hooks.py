# JupyterHub hooks and configuration

import os
import requests
import urllib.parse


KARECTL_ENV = os.environ.get("KARECTL_ENV", "stg")
KARECTL_DOMAIN = os.environ.get("KARECTL_EXTERNAL_DOMAIN", "k8tre.org")
BACKEND_URL = os.environ.get(
    "KARECTL_BACKEND_URL",
    f"https://portal.{KARECTL_ENV}.{KARECTL_DOMAIN}"
)

def logout_hook(user):
    """ Call backend cleanup when user logs out of JupyterHub
    """
    try:
        response = requests.post(
            f"{BACKEND_URL}/api/cleanup-session",
            headers={"X-Auth-User": user.name},
            timeout=5.0,
            verify=False
        )
        if response.status_code == 200:
            print(f"Successfully cleaned up session for user: {user.name}")
        else:
            print(f"Cleanup request failed with status: {response.status_code}")
    except Exception as e:
        print(f"Failed to cleanup session for {user.name}: {e}")

def get_project_from_query(spawner):
    """ Parse project from query param in spawn_url.
    """
    url = spawner.user._spawn_pending.get('url', '') if hasattr(spawner.user, '_spawn_pending') else ''
    if not url:
        url = spawner.user.settings.get('spawn_url', '')
    if not url:
        return None

    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    project = query.get('project', [None])[0]
    return project

async def pre_spawn_hook(spawner):
    """ Hook to run before spawning a new server
    """
    # Debug
    headers = dict(spawner.handler.request.headers)
    spawner.log.info(f"Incoming headers for pre_spawn_hook: {headers}")

    # Extract project from scoped username
    username = spawner.user.name
    # Parse project from username
    if '-' in username:
        parts = username.rsplit('-', 1)
        base_user = parts[0]
        project = parts[1]
        spawner.log.info(f"Extracted base_user: {base_user}, project: {project}")
    else:
        base_user = username
        project = None
        spawner.log.warning(f"Username '{username}' is not project-scoped!")

    # Validate project from headers
    header_project = headers.get("X-Auth-Project", "")
    if header_project and project:
        if header_project != project:
            raise ValueError(f"Project context mismatch: header={header_project}, username={project}")
        spawner.log.info(f"Project validation passed: {project}")
    elif not project:
        spawner.log.warning("No project context in username")

    # Set environment variables
    spawner.environment = spawner.environment or {}
    spawner.environment["KARECTL_USER"] = base_user
    spawner.environment["KARECTL_BASE_USER"] = base_user
    spawner.environment["KARECTL_PROJECT"] = project or ""
    spawner.environment["SELECTED_PROJECT"] = project or ""

    spawner.log.info(f"Spawner environment set: USER={base_user}, PROJECT={project}")

# Configure JupyterHub settings
c.JupyterHub.bind_url = "http://:8081"
c.JupyterHub.hub_connect_url = "http://hub.jupyterhub.svc.cluster.local:8081"
c.JupyterHub.logout_redirect_url = f"{BACKEND_URL}/logged-out"
c.Authenticator.logout_redirect_url = f"{BACKEND_URL}/logged-out"
c.JupyterHub.post_stop_hook = logout_hook
c.KubeSpawner.pre_spawn_hook = pre_spawn_hook

# Additional settings that were in 04-custom-templates.py
c.JupyterHub.allow_named_servers = False
c.JupyterHub.redirect_to_server = False
