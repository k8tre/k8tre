# Custom KubeSpawner with dynamic profile management

import os
import urllib.parse
import requests
from kubespawner import KubeSpawner


KARECTL_ENV = os.environ.get("KARECTL_ENV", "stg")
KARECTL_DOMAIN = os.environ.get("KARECTL_EXTERNAL_DOMAIN", "k8tre.org")
BACKEND_URL = os.environ.get(
    "KARECTL_BACKEND_URL",
    f"https://portal.{KARECTL_ENV}.{KARECTL_DOMAIN}"
)

def get_available_projects():
    """ Call the backend API to fetch available projects
    """
    try:
        response = requests.get(
            f"{BACKEND_URL}/api/projects",
            verify=False,
            timeout=30
        )
        if response.status_code == 200:
            data = response.json()
            return [project['name'] for project in data.get('projects', [])]
        else:
            return []
    except Exception as e:
        print(f"Error fetching projects from backend: {e}")
        return []

def get_project_from_spawner_user(spawner):
    """Extract project from the scoped username
    """
    try:
        username = spawner.user.name
        if '-' in username:
            parts = username.rsplit('-', 1)  # Split from right to handle usernames with dashes
            if len(parts) == 2:
                project = parts[1]
                spawner.log.info(f"Profile filtering - Extracted project from username: {project}")
                return project

        spawner.log.warning(f"Profile filtering - Could not extract project from username: {username}")
    except Exception as e:
        spawner.log.error(f"Error extracting project from username: {e}")

    return None

def get_project_from_request_uri(spawner):
    """ Extract project from current request URI
    """
    try:
        request_uri = spawner.handler.request.uri if hasattr(spawner, 'handler') and spawner.handler else ""
        spawner.log.info(f"Profile filtering - Request URI: {request_uri}")

        if "?" in request_uri:
            query_string = request_uri.split("?", 1)[1]
            query_params = urllib.parse.parse_qs(query_string)
            project = query_params.get('project', [None])[0]
            if project:
                available_projects = get_available_projects()
                if project in available_projects:
                    spawner.log.info(f"Profile filtering - Found project: {project}")
                    return project

        # Only use as last resort fallback
        if hasattr(spawner, 'handler') and spawner.handler:
            auth_project = spawner.handler.request.headers.get('X-Auth-Project', '')
            if auth_project:
                spawner.log.info(f"Profile filtering project: {auth_project}")
                return auth_project

    except Exception as e:
        spawner.log.error(f"Error extracting project from request URI: {e}")

    return None

def get_workspaces(spawner: KubeSpawner):
    """ Fetch available workspaces/profiles for the current user and project
    """
    try:
        spawner.log.info("=== GET_WORKSPACES FUNCTION CALLED ===")

        # Extract project from authenticated username
        requested_project = get_project_from_spawner_user(spawner)

        # Fallback to request URI/headers
        if not requested_project:
            spawner.log.warning("Could not extract project from username, trying request URI as fallback")
            requested_project = get_project_from_request_uri(spawner)

        if requested_project:
            response = requests.get(
                f'{BACKEND_URL}/internal/projects/{requested_project}/profiles',
                verify=False,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                profiles = data.get('profiles', [])
                spawner.log.info(f"Fetched profiles for project '{requested_project}': {[p['display_name'] for p in profiles]}")
                return profiles
            else:
                spawner.log.error(f"Failed to fetch profiles for project {requested_project}: {response.status_code}")
        else:
            spawner.log.error("No project could be determined - cannot fetch profiles")
            return []

    except Exception as e:
        spawner.log.error(f"Error calling backend API for profiles: {e}")
        return []

# Configure the spawner
c.KubeSpawner.profile_list = get_workspaces
