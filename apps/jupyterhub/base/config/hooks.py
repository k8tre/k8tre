# JupyterHub hooks and configuration

import os
import re
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


def get_notebook_pvc_name(username, project):
    """ Get notebook PVC by cr8tor naming convention
    """
    safe_user = re.sub(r"[^a-z0-9-]", "", username.lower())
    safe_project = re.sub(r"[^a-z0-9-]", "", project.lower())
    return f"notebook-{safe_user}-{safe_project}"


async def pre_spawn_hook(spawner):
    """ Hook to run before spawning a new server
    """
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

    # Set project namespace and labels
    if project:
        spawner.extra_labels = spawner.extra_labels or {}
        spawner.extra_labels['karectl.io/project'] = project
        spawner.extra_labels['karectl.io/user'] = base_user

        namespace = f"project-{project}"
        spawner.namespace = namespace
        spawner.log.info(f"Spawning into project namespace: {namespace}")

        # Configure notebook storage using cr8tor's PVC naming convention
        # PVC is pre-created by cr8tor when user joins project
        pvc_name = get_notebook_pvc_name(base_user, project)
        spawner.log.info(f"Using notebook PVC: {pvc_name} in namespace {namespace}")

        spawner.volumes = spawner.volumes or []
        spawner.volume_mounts = spawner.volume_mounts or []

        # Mount the pre-provisioned PVC at /home/jovyan
        # If PVC doesn't exist, Kubernetes will fail to schedule the pod
        spawner.volumes.append({
            'name': 'notebook-storage',
            'persistentVolumeClaim': {'claimName': pvc_name}
        })
        spawner.volume_mounts.append({
            'name': 'notebook-storage',
            'mountPath': '/home/jovyan'
        })

        spawner.environment["NOTEBOOK_STORAGE_TYPE"] = "persistent"
        spawner.environment["NOTEBOOK_PVC_NAME"] = pvc_name
        spawner.log.info(f"Persistent storage configured: PVC {pvc_name} mounted at /home/jovyan")

    spawner.log.info(f"Spawner environment set: USER={base_user}, PROJECT={project}")

# Configure JupyterHub settings
c.JupyterHub.bind_url = "http://:8081"
c.JupyterHub.hub_connect_url = "http://hub.jupyterhub.svc.cluster.local:8081"
c.JupyterHub.logout_redirect_url = f"{BACKEND_URL}/logged-out"
c.Authenticator.logout_redirect_url = f"{BACKEND_URL}/logged-out"
c.JupyterHub.post_stop_hook = logout_hook
c.KubeSpawner.pre_spawn_hook = pre_spawn_hook

# Enable user namespaces to handle per-user/per-project namespaces
c.KubeSpawner.enable_user_namespaces = True

# Additional settings that were in 04-custom-templates.py
c.JupyterHub.allow_named_servers = False
c.JupyterHub.redirect_to_server = False
