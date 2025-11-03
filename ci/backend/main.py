import os
import re
import httpx
import hmac
import hashlib
import jwt
import time
import asyncio
import socket
import urllib.parse
from urllib.parse import urlparse, parse_qs
import json
from base64 import standard_b64encode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from authlib.integrations.starlette_client import OAuth
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Depends, HTTPException, Header, Query
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi import Path
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi import HTTPException as FastAPIHTTPException
from jwt import PyJWKClient
from starlette.middleware.sessions import SessionMiddleware
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException


# Load env variables
load_dotenv()

KARECTL_ENV = os.environ.get("KARECTL_ENV", "dev")
KARECTL_EXTERNAL_DOMAIN = os.environ.get("KARECTL_EXTERNAL_DOMAIN", "k8tre.internal")
KARECTL_PLATFORM = os.environ.get("KARECTL_PLATFORM", "k3s")

def build_service_url(service, path=""):
    """ Build service URL using configured environment and domain """
    return f"https://{service}.{KARECTL_ENV}.{KARECTL_EXTERNAL_DOMAIN}{path}"

def get_session_domain():
    """ Get cookie domain for session management """
    return f".{KARECTL_ENV}.{KARECTL_EXTERNAL_DOMAIN}"


GUACAMOLE_HOST = os.environ.get("GUACAMOLE_HOST", build_service_url("guacamole"))
KARECTL_BACKEND = os.environ.get("KARECTL_BACKEND", build_service_url("backend"))

JSON_SECRET_KEY = os.environ["JSON_SECRET_KEY"]
AUTH_SIG_SECRET = os.environ.get("AUTH_SIG_SECRET", "change-me")
AUTH_SIG_TTL = int(os.environ.get("AUTH_SIG_TTL", "60"))
MAX_RETRIES = 10
STATIC_ALLOWLIST_PATTERNS = [
    r"^/guacamole/api/patches$",
    r"^/guacamole/api/languages$",
    r"^/guacamole/api/.*",  # Allow all Guacamole API calls
    r"^/guacamole/assets/.*",
    r"^/guacamole/translations/.*",
    r"^/guacamole/fonts/.*",
    r"^/guacamole/images/.*",
    r"^/guacamole/.*\.(js|css|png|svg|woff2?|ico|ttf|map)$",
]
STATIC_RESOURCE_CONFIG = {
    "patterns": [
        "/hub/static/",
        "/static/",
        "/favicon.ico",
        "/hub/favicon.ico",
        "/hub/logo",
    ],
    "extensions": [
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico",
        ".svg", ".woff", ".woff2", ".ttf", ".eot", ".map", ".json",
        ".webp", ".avif", ".webm", ".mp4"
    ],
    "enabled": True
}


app = FastAPI()

# login sessions
# temp for http
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("SESSION_SECRET", "dev-secret-key"),
    session_cookie="karectl-session",
    same_site="lax",
    https_only=False,
    max_age=86400 * 2
)
# Will update once we confirm from the Azure App gateway integration using env
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        build_service_url("jupyter"),
        build_service_url("guacamole"),
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

oauth = OAuth()

keycloak_internal_url = os.environ.get(
    "KEYCLOAK_INTERNAL_URL", 
    "http://keycloak.keycloak"
)
keycloak_external_url = os.environ.get("KEYCLOAK_EXTERNAL_URL", build_service_url("keycloak"))
keycloak_realm = os.environ.get("KEYCLOAK_REALM", "karectl-app")

internal_base = f"{keycloak_internal_url}/realms/{keycloak_realm}"
external_base = f"{keycloak_external_url}/realms/{keycloak_realm}"
jwks_url = f"{keycloak_internal_url}/realms/{keycloak_realm}/protocol/openid-connect/certs"

oauth.register(
    name='keycloak',
    client_id=os.environ["KEYCLOAK_CLIENT_ID"],
    client_secret=os.environ["KEYCLOAK_CLIENT_SECRET"],
    authorize_url=f"{external_base}/protocol/openid-connect/auth",    
    access_token_url=f"{internal_base}/protocol/openid-connect/token",
    userinfo_url=f"{internal_base}/protocol/openid-connect/userinfo", 
    jwks_uri=f"{external_base}/protocol/openid-connect/certs",        
    end_session_url=f"{external_base}/protocol/openid-connect/logout",
    issuer=external_base,
    client_kwargs={
        'scope': 'openid profile email groups offline_access',
        'token_endpoint_auth_method': 'client_secret_post',
        'timeout': httpx.Timeout(30.0),
        'verify': False
    }
)

NAMESPACE = os.environ.get("KARECTL_NAMESPACE", "default")

# K8s config
try:
    config.load_incluster_config()
except Exception:
    config.load_kube_config()
k8s_api = client.CustomObjectsApi()

active_user_sessions = {}

# All custom routes

def _hmac_sign(hex_key: str, message: bytes):
    """ Creation of HMAC headers for signed authentication
    """
    key = bytes.fromhex(hex_key)
    return hmac.new(key, message, hashlib.sha256).digest()

def _aes256_cbc_encrypt(hex_key: str, message: bytes):
    """ AES 256 encryption logic (standard approach for headers)
    """
    null_iv = bytes.fromhex("00" * 16)
    key = bytes.fromhex(hex_key)
    # PKCS7 padding
    pad = 16 - (len(message) % 16)
    message += bytes([pad] * pad)
    cipher = Cipher(algorithms.AES256(key), modes.CBC(null_iv))
    encryptor = cipher.encryptor()
    return encryptor.update(message) + encryptor.finalize()

async def _get_guac_auth_token(data: dict):
    """ Creating a guacamole token for the authentication headers
    """
    # Sign and encrypt (signature + JSON)
    payload = json.dumps(data, separators=(",", ":")).encode()
    sig = _hmac_sign(JSON_SECRET_KEY, payload)
    ct = _aes256_cbc_encrypt(JSON_SECRET_KEY, sig + payload)

    # Push based authentication logic for guacamole json auth-headers
    body = "data=" + urllib.parse.quote(standard_b64encode(ct).decode())
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    async with httpx.AsyncClient(timeout=30, verify=False) as client:
        r = await client.post(f"{GUACAMOLE_HOST}/guacamole/api/tokens", data=body, headers=headers)
        r.raise_for_status()
        return r.json()["authToken"]

def _build_connections_for_user(username):
    """ Create vdi connections pers user which are already created
        We filter those existing CRDs based on user name
    """
    conns = {}
    crd = k8s_api.list_namespaced_custom_object(
        group="karectl.io", version="v1alpha1", namespace="jupyterhub", plural="vdiinstances"
    )

    for vdi in crd.get("items", []):
        spec = vdi.get("spec", {})
        status = vdi.get("status", {})
        v_user = spec.get("user")
        v_proj = spec.get("project")
        pwd = status.get("password")
        phase = status.get("phase", "Unknown")
        vdi_name = vdi.get("metadata", {}).get("name", "unknown")
        print(f"Checking VDI {vdi_name}: user={v_user}, project={v_proj}, phase={phase}, has_password={bool(pwd)}", flush=True)
        if v_user == username and pwd and phase in ("Ready", "Running"):
            conn_id = f"{v_proj}-desktop"
            print(f"Adding connection: {conn_id} for VDI {vdi_name}", flush=True)
            hostname = f"vdi-{v_user}-{v_proj}.jupyterhub.svc.cluster.local"
            conns[conn_id] = {
                "protocol": "rdp",
                "parameters": {
                    "hostname": hostname,
                    "port": "3389",
                    "username": "ubuntu",
                    "password": pwd,
                    "ignore-cert": "true",
                    "security": "any",
                    "resize-method": "reconnect",
                    "enable-drive": "true",
                    "create-drive-path": "true",
                    "console": "true",
                    "disable-auth": "true",
                    "color-depth": "32",
                },
            }
    return conns


def _sign(user, project, audience):
    """ Create a unique signature for the header authentication.
    """
    stamp = str(int(time.time()))
    payload = f"{user}|{project}|{audience}|{stamp}".encode()
    signature = hmac.new(AUTH_SIG_SECRET.encode(), payload, hashlib.sha256).hexdigest()
    return stamp, signature, audience


async def refresh_access_token(request: Request):
    """ Refresh access token using refresh token
    """
    refresh_token = request.session.get("refresh_token")
    if not refresh_token:
        print("No refresh token available", flush=True)
        return None
    
    try:
        print("Attempting to refresh access token...", flush=True)
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(
                f"{internal_base}/protocol/openid-connect/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": os.environ["KEYCLOAK_CLIENT_ID"],
                    "client_secret": os.environ["KEYCLOAK_CLIENT_SECRET"],
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
        
        if response.status_code == 200:
            token_data = response.json()
            # Update session with new tokens
            request.session["token"] = token_data["access_token"]
            if "refresh_token" in token_data:
                request.session["refresh_token"] = token_data["refresh_token"]
            
            # Update user information
            if "id_token" in token_data:
                request.session["id_token"] = token_data["id_token"]
            
            print("Token refreshed successfully", flush=True)
            return token_data["access_token"]
        else:
            print(f"Token refresh failed: {response.status_code} - {response.text}", flush=True)
            
    except Exception as e:
        print(f"Token refresh error: {e}", flush=True)
    
    return None

def check_token_expiry(token):
    """ To check if token is expired or expires soon (within 5 minutes)
    """
    if not token:
        return True, 0
    
    try:
        # Decode without verification to check expiry
        decoded = jwt.decode(token, options={"verify_signature": False})
        exp = decoded.get('exp', 0)
        current_time = int(time.time())
        
        # Consider expired if expires within 5 minutes (300 seconds)
        expires_soon = (exp - current_time) < 300
        time_left = exp - current_time
        
        return expires_soon, time_left
    except Exception as e:
        print(f"Token expiry check failed: {e}", flush=True)
        return True, 0

async def ensure_valid_token(request: Request):
    """ Ensure we have a valid access token, refresh if needed
    """
    token = request.session.get("token")
    
    if not token:
        print("No token in session", flush=True)
        return None
    
    expires_soon, time_left = check_token_expiry(token)
    
    if expires_soon:
        print(f"Token expires in {time_left} seconds, refreshing...", flush=True)
        new_token = await refresh_access_token(request)
        if new_token:
            return new_token
        else:
            print("Token refresh failed, user needs to re-login", flush=True)
            return None
    else:
        print(f"Token is valid for {time_left} more seconds", flush=True)
        return token

def verify_token(auth_header):
    """ Verify token whether it is valid or not.
    """
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorisation header")

    token = auth_header.split(" ", 1)[1]

    import ssl
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    jwks_client = PyJWKClient(jwks_url, ssl_context=ssl_context)
    signing_key = jwks_client.get_signing_key_from_jwt(token)

    expected_issuer = f"{build_service_url('keycloak')}/realms/{keycloak_realm}"

    try:
        decoded = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=os.environ["KEYCLOAK_CLIENT_ID"],
            issuer=expected_issuer
        )
        return decoded
    except Exception as e:
        print(f"Token verification failed: {e}", flush=True)
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/", response_class=HTMLResponse)
async def homepage(request: Request):
    """ Main route for the homepage
    """
    user = request.session.get("user")
    if not user:
        return templates.TemplateResponse("login.html", {"request": request})

    username = user.get("preferred_username")
    return templates.TemplateResponse(
        "home.html", {"request": request, "user": user, "username": username}
    )

@app.options("/login")
async def login_options():
    """ Login option to return it is valid on subsequent requests.
    """
    return Response(status_code=204)

@app.get("/login")
async def login(request: Request):
    """ Main route to login with the backend service.
    """
    request.session.clear()
    redirect_uri = build_service_url("backend", "/auth/callback")
    print(f"Login redirect URI: {redirect_uri}", flush=True)

    return await oauth.keycloak.authorize_redirect(request, redirect_uri)

@app.get("/auth/callback")
async def auth_callback(request: Request):
    """  Call back function to retrieve the login details based on keycloak.
    """
    try:
        if "_state" in request.session:
            print(f"Found existing state: {request.session.get('_state')}", flush=True)

        token = await oauth.keycloak.authorize_access_token(request)
        access_token = token.get('access_token') if hasattr(token, 'get') else token['access_token']
        refresh_token = token.get('refresh_token')
        userinfo_url = f"{keycloak_internal_url}/realms/{keycloak_realm}/protocol/openid-connect/userinfo"

        async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
            response = await client.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
        if response.status_code == 200:
            user = response.json()
            username = user.get('preferred_username', 'unknown')
            print(f"User authenticated: {username}", flush=True)
            
            request.session["user"] = dict(user)
            request.session["token"] = access_token
            request.session["refresh_token"] = refresh_token
            request.session["session_created"] = int(time.time())

            # Store session info for cleanup
            active_user_sessions[username] = {
                "token": access_token,
                "refresh_token": refresh_token,
                "session_id": request.session.get("_session_id", "unknown")
            }
            print(f"Session after storing user: {dict(request.session)}", flush=True)
            return RedirectResponse("/")
        else:
            raise Exception(f"Userinfo request failed: {response.status_code} - {response.text}")

    except Exception as e:
        print(f"Auth callback error: {e}", flush=True)
        print(f"Error type: {type(e).__name__}", flush=True)
        print(f"Error details: {repr(e)}", flush=True)
        import traceback
        print(f"Traceback: {traceback.format_exc()}", flush=True)
        request.session.clear()
        return RedirectResponse("/")

@app.get("/logout")
async def logout(request: Request):
    """ Route to call the logout
    """
    user = request.session.get("user")
    username = user.get("preferred_username") if user else "unknown"
    token = request.session.get("token")
    refresh_token = request.session.get("refresh_token")

    request.session.clear()
    
    if username in active_user_sessions:
        del active_user_sessions[username]
    
    await revoke_user_tokens(username, token, refresh_token)
    response = RedirectResponse("/logged-out")
    response.delete_cookie("karectl-session")
    return response

@app.get("/logged-out", response_class=HTMLResponse)
async def logged_out(request: Request):
    """ Simple logged out page that doesn't require authentication
    """
    return templates.TemplateResponse("logged_out.html", {"request": request})

async def revoke_user_tokens(username, token=None, refresh_token=None):
    """ Revoke tokens for a specific user
    """
    try:
        async with httpx.AsyncClient(verify=False) as client:
            if token:
                await client.post(
                    f"{internal_base}/protocol/openid-connect/revoke",
                    data={
                        "token": token,
                        "token_type_hint": "access_token",
                        "client_id": os.environ["KEYCLOAK_CLIENT_ID"],
                        "client_secret": os.environ["KEYCLOAK_CLIENT_SECRET"],
                    }
                )
            if refresh_token:
                await client.post(
                    f"{internal_base}/protocol/openid-connect/revoke",
                    data={
                        "token": refresh_token,
                        "token_type_hint": "refresh_token",
                        "client_id": os.environ["KEYCLOAK_CLIENT_ID"],
                        "client_secret": os.environ["KEYCLOAK_CLIENT_SECRET"],
                    }
                )
    except Exception as e:
        pass

@app.post("/api/cleanup-session")
async def cleanup_session(request: Request):
    """ Clean up backend session when JupyterHub logs out
    """
    # Get user info from auth headers
    username = request.headers.get("X-Auth-User")
    
    if not username:
        return {"status": "no_user"}
    
    # Get stored tokens for this user
    user_session = active_user_sessions.get(username)
    if user_session:
        await revoke_user_tokens(
            username, 
            user_session.get("token"), 
            user_session.get("refresh_token")
        )
        
    del active_user_sessions[username]

    return {"status": "cleaned", "user": username}

@app.get("/api/context")
def api_context(
    authorisation=Header(None, alias="Authorization"),
    user=Query(None)
):
    """ API call to get the current context information based on keycloak
        (Include user, project and groups)
    """
    claims = verify_token(authorisation)
    username = claims.get("preferred_username")
    if user and user != username:
        raise HTTPException(status_code=403, detail="User mismatch")

    try:
        user_cr = k8s_api.get_namespaced_custom_object(
            "identity.karectl.io", "v1alpha1", NAMESPACE, "users", username)
    except Exception as e:
        return JSONResponse({"error": f"User CR not found: {e}"}, status_code=404)

    groups = user_cr['spec'].get('groups', [])
    projects = {}
    for group_name in groups:
        try:
            group_cr = k8s_api.get_namespaced_custom_object(
                "identity.karectl.io", "v1alpha1", NAMESPACE, "groups", group_name)

            for proj in group_cr['spec'].get('projects', []):
                if proj not in projects:
                    proj_cr = k8s_api.get_namespaced_custom_object(
                        "research.karectl.io", "v1alpha1", NAMESPACE, "projects", proj)
                    projects[proj] = {
                        "name": proj,
                        "description": proj_cr['spec'].get('description', ''),
                        "apps": proj_cr['spec'].get('apps', [])
                    }
        except Exception:
            continue

    return {
        "user": username,
        "groups": groups,
        "projects": list(projects.values())
    }

@app.get("/auth/validate")
async def auth_validate(request: Request):
    """ Function to validate each subsequent requests from application against keycloak or
        login information.

        This is the main important function which decides the overall flow and control on how each application
        behaves and works with backend service.
    """
    o_param = request.query_params.get("orig")

    # Figure out original URL (from ingress-safe headers)
    orig = o_param or (
        request.headers.get("x-original-url")
        or request.headers.get("x-auth-request-redirect")
        or request.headers.get("x-original-uri")
        or request.url.path
    )
    scheme = request.headers.get("x-forwarded-proto", "http")
    host = request.headers.get("x-original-host") or request.headers.get("host", "")

    original = f"{scheme}://{host}{orig}" if orig.startswith("/") else orig
    original = urllib.parse.unquote(original)

    p = urllib.parse.urlparse(original)
    q = urllib.parse.parse_qs(p.query)
    path = p.path

    print(f"Auth/validate original: {original}", flush=True)

    # Special handling for Guacamole tunnel endpoints
    # These use Guacamole's auth token in query params, not JWT
    is_tunnel_endpoint = path.startswith("/guacamole/tunnel") or path.startswith("/guacamole/websocket-tunnel")
    if is_tunnel_endpoint:
        print(f"Tunnel endpoint detected: {path}", flush=True)
        print(f"  Headers: x-auth-token-cookie={request.headers.get('x-auth-token-cookie', 'NOT PRESENT')}", flush=True)
        print(f"  Cookie header: {request.headers.get('cookie', 'NOT PRESENT')[:100]}", flush=True)
        print(f"  Authorization: {request.headers.get('authorization', 'NOT PRESENT')}", flush=True)

    # Allowlisted static
    if is_static_resource(original):
        return Response(status_code=200)

    # We'll get JWT from cookies/headers instead for proper authentication
    if is_tunnel_endpoint:
        token = None
    else:
        token = q.get("token", [None])[0]

    project = q.get("project", [None])[0]
    if not project:
        project = request.cookies.get("karectl-project", "")
    
    if not token and path.startswith("/hub/login") and "next" in q:
        np = urllib.parse.urlparse(q["next"][0])
        same_host_or_path = (not np.netloc) or (np.netloc == p.netloc)
        if same_host_or_path and np.path.startswith(("/hub", "/user/")):
            nq = urllib.parse.parse_qs(np.query)
            token = token or (nq.get("token") or [None])[0]
            project = project or (nq.get("project") or [""])[0]
            print("Using token from next= param", flush=True)

    # If not available, try from Authorization header for every path
    if not token:
        ah = request.headers.get("authorization", "")
        if ah.startswith("Bearer "):
            token = ah.split(" ", 1)[1]
            print("Using token from Authorization header", flush=True)

    if not token:
        auth_token_header = request.headers.get("x-auth-token-cookie")
        if auth_token_header:
            try:
                # Verify the cookie token is valid
                claims = verify_token(f"Bearer {auth_token_header}")
                username = claims.get("preferred_username")
                if username:
                    token = auth_token_header
                    print(f"Using auth token from nginx header for user: {username}", flush=True)
            except Exception as e:
                print(f"Auth token header verification failed: {e}", flush=True)

    # Project from nginx-forwarded project cookie header
    if not project:
        project_header = request.headers.get("x-project-cookie")
        if project_header:
            project = project_header
            print(f"Using project from nginx header: {project}", flush=True)

    if not token or not project:
        cookie_header = request.headers.get("cookie", "")
        if cookie_header:
            # Parse cookies manually
            cookies = {}
            for cookie_pair in cookie_header.split(';'):
                cookie_pair = cookie_pair.strip()
                if '=' in cookie_pair:
                    key, value = cookie_pair.split('=', 1)
                    cookies[key.strip()] = value.strip()

            # Look for auth token
            if not token and 'karectl-auth-token' in cookies:
                auth_cookie = cookies['karectl-auth-token']
                try:
                    claims = verify_token(f"Bearer {auth_cookie}")
                    username = claims.get("preferred_username")
                    if username:
                        token = auth_cookie
                except Exception as e:
                    print(f"Cookie auth token verification failed: {e}", flush=True)

            # Look for project
            if not project and 'karectl-project' in cookies:
                project = cookies['karectl-project']

    # If not available, try from server side session via cookie
    if not token:
        token = request.session.get("token")

    if not token:
        referer = request.headers.get("referer", "")
        if referer:
            try:
                parsed_referer = urllib.parse.urlparse(referer)
                referer_query = urllib.parse.parse_qs(parsed_referer.query)
                token = referer_query.get("token", [None])[0]

                # Also get project from referer if not already set
                if not project:
                    project = referer_query.get("project", [None])[0]
            except Exception as e:
                print(f"Failed to parse referer: {e}", flush=True)

    if (path.startswith("/hub") or path.startswith("/user/")) and not token:
        print("Hub path without query token -> 401", flush=True)
        return Response(status_code=401)

    if not token:
        print("No token found -> 401", flush=True)
        return Response(status_code=401)

    # Verify JWT
    claims = verify_token(f"Bearer {token}")
    username = claims.get("preferred_username", "")

    if (path.startswith("/hub") or path.startswith("/user/")) and not project:
        print("Hub path missing ?project= -> 401", flush=True)
        return Response(status_code=401)

    # Authorization check: Verify user has access to the requested project
    if project:
        try:
            user_cr = k8s_api.get_namespaced_custom_object(
                "identity.karectl.io", "v1alpha1", NAMESPACE, "users", username
            )
            user_groups = user_cr['spec'].get('groups', [])

            # Check if user has access
            authorised = False
            for group_name in user_groups:
                try:
                    group_cr = k8s_api.get_namespaced_custom_object(
                        "identity.karectl.io", "v1alpha1", NAMESPACE, "groups", group_name
                    )
                    group_projects = group_cr['spec'].get('projects', [])
                    if project in group_projects:
                        authorised = True
                        print(f"User {username} authorised for project {project} via group {group_name}", flush=True)
                        break
                except Exception:
                    continue

            if not authorised:
                print(f"AUTHORISATION DENIED: User {username} attempted to access project {project} without permission", flush=True)
                return Response(status_code=403)

        except Exception as e:
            print(f"Authorisation check failed for user {username}: {e}", flush=True)
            return Response(status_code=403)

    # Creating all the headers that we needed for nginx annotations and authentication.
    headers = {
        "Remote-User": claims.get("preferred_username", ""),
        "X-Auth-User": claims.get("preferred_username", ""),
        "X-Auth-Email": claims.get("email", ""),
        "X-Auth-Groups": ",".join(claims.get("groups", []) or []),
        "X-Auth-Project": project,
        "Authorization": f"Bearer {token}",
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Vary": "Cookie, Authorization",
    }

    if path.startswith("/hub") or path.startswith("/user/"):
        stamp, sig, aud = _sign(headers["X-Auth-User"], headers["X-Auth-Project"], "jupyterhub")
        headers["X-Auth-Stamp"] = stamp
        headers["X-Auth-Signature"] = sig
        headers["X-Auth-Audience"] = aud

    return Response(status_code=200, headers=headers)

def is_static_resource(url, config=None):
    """ To identify whether a request is for static, non-authenticated urls
        Eg: Call to access icons, internal API calls etc.
    """
    if config is None:
        config = STATIC_RESOURCE_CONFIG

    if not config.get("enabled", True):
        return False
        
    # Check patterns first
    for pattern in config.get("patterns", []):
        if pattern in url:
            return True
    
    # Check file extensions
    for ext in config.get("extensions", []):
        if url.endswith(ext):
            return True
    
    path = urlparse(url).path
    for pattern in STATIC_ALLOWLIST_PATTERNS:
        if re.match(pattern, path):
            return True
            
    return False

def require_user(request: Request):
    """ To check whether user is present in a request call or not.
    """
    user = request.session.get("user")

    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

@app.exception_handler(FastAPIHTTPException)
async def custom_http_exception_handler(request: Request, exc: FastAPIHTTPException):
    """ Custom error handler for the Fast API
    """
    if exc.status_code == 401:
        return templates.TemplateResponse(
            "error.html", 
            {"request": request, "error": "You are not authenticated. Please login to continue."},
            status_code=401
        )

    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": str(exc.detail)}
    )

@app.get("/projects", response_class=HTMLResponse)
def get_projects(request: Request, user=Depends(require_user)):
    """ To access all the projects from the CRDs
    """
    # user's groups
    username = user["preferred_username"]
    try:
        user_cr = k8s_api.get_namespaced_custom_object(
            "identity.karectl.io", "v1alpha1", NAMESPACE, "users", username)
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": f"User CR not found: {e}"})

    groups = user_cr['spec'].get('groups', [])
    projects = set()
    for group_name in groups:
        try:
            group_cr = k8s_api.get_namespaced_custom_object(
                "identity.karectl.io", "v1alpha1", NAMESPACE, "groups", group_name)
            projects.update(group_cr['spec'].get('projects', []))
        except Exception:
            continue

    project_objs = []
    for proj in projects:
        try:
            project = k8s_api.get_namespaced_custom_object(
                "research.karectl.io", "v1alpha1", NAMESPACE, "projects", proj)
            project_objs.append({
                "name": proj,
                "description": project['spec'].get('description', '')
            })
        except Exception:
            continue

    return templates.TemplateResponse(
        "projects.html",
        {"request": request, "projects": project_objs}
    )

@app.get("/projects/{project}/apps", response_class=HTMLResponse)
def get_apps(project: str, request: Request, user=Depends(require_user)):
    """ To get all the applications supported for a specified project (Per project configurations)
        Eg: Asthma project supports Jupyerhuab and guacamole, but
            Diabetes project supports only Jupyterhub instance and not vdi
    """
    try:
        project_cr = k8s_api.get_namespaced_custom_object(
            "research.karectl.io", "v1alpha1", NAMESPACE, "projects", project)
        apps = project_cr['spec'].get('apps', [])
        return templates.TemplateResponse(
            "apps.html",
            {"request": request, "project": project, "apps": apps}
        )

    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "error": f"Project not found: {e}"})

@app.get("/internal/projects/{project}/profiles")
def get_profiles_internal(project: str):
    """ To get all the profiles associated with a project
        It is mainly used for jupyterhub custom spawn
    """
    try:
        print(f"Fetching profiles for project: {project}", flush=True)
        project_cr = k8s_api.get_namespaced_custom_object(
            "research.karectl.io", "v1alpha1", NAMESPACE, "projects", project
        )
        profiles = project_cr['spec'].get('profiles', [])
        print(f"Profiles for project '{project}': {profiles}", flush=True)
        return JSONResponse(content={"profiles": profiles})
    
    except Exception as e:
        print(f"Error fetching profiles for project '{project}': {e}", flush=True)
        return JSONResponse(
            {"error": f"Project not found: {e}"}, 
            status_code=404
        )

@app.get("/auth/sso")
async def sso_redirect(
    token: str = Query(...),
    project: str = Query(...),
    app: str = Query(default="jupyter")
):
    """SSO endpoint for VDI desktop shortcuts - authenticates with JWT token and sets cookies"""
    try:
        claims = verify_token(f"Bearer {token}")
        username = claims.get("preferred_username")
        email = claims.get("email", "")

        print(f"SSO authentication for user: {username}, project: {project}, app: {app}", flush=True)

        # Build redirect URL based on app
        if app == "jupyter":
            redirect_url = build_service_url("jupyter", "/hub")
        elif app == "guacamole":
            redirect_url = build_service_url("guacamole", "/guacamole/")
        else:
            redirect_url = build_service_url("backend", "/")

        response = RedirectResponse(redirect_url)
        cookie_domain = get_session_domain()

        response.set_cookie(
            "karectl-project",
            project,
            samesite="lax",
            secure=False,
            httponly=False,
            domain=cookie_domain,
            path="/"
        )

        response.set_cookie(
            "karectl-auth-token",
            token,
            samesite="lax",
            secure=False,
            httponly=True,
            domain=cookie_domain,
            max_age=3600,
            path="/"
        )

        print(f"SSO cookies set for {username}, redirecting to {redirect_url}", flush=True)
        return response

    except Exception as e:
        print(f"SSO authentication failed: {e}", flush=True)
        raise HTTPException(status_code=401, detail=f"SSO authentication failed: {e}")

@app.get("/launch/{project}/{app}")
async def launch_app(project: str, app: str, request: Request, user=Depends(require_user)):
    """ To launch an application from the backend service
    """
    username = user["preferred_username"]
    email = user.get("email", "")
    print(f"Session user: {request.session.get('user', 'NO SESSION USER')}", flush=True)

    valid_token = await ensure_valid_token(request)
    if not valid_token:
        print("No valid token available, redirecting to login", flush=True)
        return RedirectResponse("/login")

    request.session["token"] = valid_token
    request.session["current_project"] = project
    request.session["user"] = user
    try:
        project_cr = k8s_api.get_namespaced_custom_object(
            "research.karectl.io", "v1alpha1", NAMESPACE, "projects", project)
        app_cfg = next((a for a in project_cr['spec'].get('apps', []) if a['name'] == app), None)

        if not app_cfg:
            raise HTTPException(status_code=404, detail="App not found for this project")

        if app_cfg["type"] == "vdi":
            refresh_token = request.session.get("refresh_token")

            vdi_name = f"{username}-{project}"
            vdi_spec = {
                "apiVersion": "karectl.io/v1alpha1",
                "kind": "VDIInstance",
                "metadata": {
                    "name": vdi_name,
                    "namespace": "jupyterhub"
                },
                "spec": {
                    "user": username,
                    "project": project,
                    "image": "ghcr.io/alwin-k-thomas/vdi-mate:latest",
                    "connection": "rdp",
                    "env": [
                        {"name": "KARECTL_TOKEN", "value": valid_token},
                        {"name": "KARECTL_REFRESH_TOKEN", "value": refresh_token},
                        {"name": "KARECTL_PROJECT", "value": project},
                        {"name": "KARECTL_USER", "value": username},
                        {"name": "KARECTL_BACKEND_URL", "value": build_service_url("backend")},
                        {"name": "KARECTL_SESSION_ID", "value": request.session.get("_session_id", "")},
                        {"name": "KARECTL_ENVIRONMENT", "value": KARECTL_ENV},
                        {"name": "KARECTL_DOMAIN", "value": KARECTL_EXTERNAL_DOMAIN}
                    ]
                }
            }

            crd_client = client.CustomObjectsApi()
            vdi_created = False
            try:
                crd_client.create_namespaced_custom_object(
                    group="karectl.io",
                    version="v1alpha1",
                    namespace="jupyterhub",
                    plural="vdiinstances",
                    body=vdi_spec
                )
                vdi_created = True
                print(f"Created new VDI instance: {vdi_name}", flush=True)
            except ApiException as e:
                if e.status == 409:
                    print(f"VDI instance {vdi_name} already exists", flush=True)
                else:
                    raise

            # Redirect to status page - it will wait for VDI to be ready
            status_url = build_service_url("backend", f"/vdi/status/{username}/{project}")
            print(f"Redirecting to status page: {status_url}", flush=True)
            return RedirectResponse(status_url)


        original_host = request.headers.get("x-original-host", "")
        x_forwarded_host = request.headers.get("x-forwarded-host", "")
        referer = request.headers.get("referer", "")

        app_url = build_service_url("jupyter", "/hub")

        # Get user's token from session and add to URL
        separator = "&" if "?" in app_url else "?"
        app_url = f"{app_url}{separator}token={valid_token}&project={project}"

        cookie_domain = get_session_domain()

        resp = RedirectResponse(app_url)
        resp.set_cookie(
            "karectl-project",
            project,
            samesite="lax",
            secure=False,
            httponly=False,
            domain=cookie_domain,
            path="/"
        )

        resp.set_cookie(
            "karectl-auth-token",
            valid_token,
            samesite="lax",
            secure=False,
            httponly=True,
            domain=cookie_domain,
            max_age=3600,
            path="/"
        )

        return resp

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=404, detail=f"Project/app not found: {e}")

@app.get("/api/projects")
def get_projects_json(user=Depends(require_user)):
    """ Get the list of projects from the CRD
    """
    username = user["preferred_username"]
    try:
        user_cr = k8s_api.get_namespaced_custom_object(
            "identity.karectl.io", "v1alpha1", NAMESPACE, "users", username)
    except Exception as e:
        return JSONResponse({"error": f"User CR not found: {e}"}, status_code=404)

    groups = user_cr['spec'].get('groups', [])
    projects = set()
    for group_name in groups:
        try:
            group_cr = k8s_api.get_namespaced_custom_object(
                "identity.karectl.io", "v1alpha1", NAMESPACE, "groups", group_name)
            projects.update(group_cr['spec'].get('projects', []))
        except Exception:
            continue

    project_objs = []
    for proj in projects:
        try:
            project = k8s_api.get_namespaced_custom_object(
                "research.karectl.io", "v1alpha1", NAMESPACE, "projects", proj)
            project_objs.append({
                "name": proj,
                "description": project['spec'].get('description', '')
            })
        except Exception:
            continue

    return {"projects": project_objs}

@app.get("/api/projects/{project}/apps")
def get_apps_json(project: str, user=Depends(require_user)):
    """ Get the list of all apps supported by a project
    """
    try:
        project_cr = k8s_api.get_namespaced_custom_object(
            "research.karectl.io", "v1alpha1", NAMESPACE, "projects", project)
        return {"apps": project_cr['spec'].get('apps', [])}
    except Exception as e:
        return JSONResponse({"error": f"Project not found: {e}"}, status_code=404)

@app.get("/api/groups")
def get_all_groups():
    """ Get all groups that we currently have from the CRD
    """
    groups = []
    try:
        group_cr_list = k8s_api.list_namespaced_custom_object(
            "identity.karectl.io", "v1alpha1", NAMESPACE, "groups"
        )
        for group_cr in group_cr_list.get("items", []):
            groups.append(group_cr["metadata"]["name"])
    except Exception as e:
        return JSONResponse({"error": f"Failed to fetch groups: {e}"}, status_code=500)

    return {"groups": groups}


@app.get("/vdi/status/{username}/{project}", response_class=HTMLResponse)
async def vdi_status_page(username: str, project: str, request: Request, user=Depends(require_user)):
    """ VDI status page
    """
    current_user = user.get("preferred_username")
    if current_user != username:
        raise HTTPException(status_code=403, detail="Access denied")

    return templates.TemplateResponse(
        "vdi-status.html",
        {"request": request, "username": username, "project": project}
    )


@app.get("/api/vdi/status/{username}/{project}")
async def get_vdi_status(username: str, project: str, user=Depends(require_user)):
    """ Get VDI instance status for polling
    """
    current_user = user.get("preferred_username")
    if current_user != username:
        raise HTTPException(status_code=403, detail="Access denied")

    instance_name = f"{username}-{project}".lower()

    try:
        vdi_cr = k8s_api.get_namespaced_custom_object(
            group="karectl.io",
            version="v1alpha1",
            namespace="jupyterhub",
            plural="vdiinstances",
            name=instance_name
        )

        status = vdi_cr.get("status", {})
        phase = status.get("phase", "Unknown")
        has_password = bool(status.get("password"))

        # Check if RDP port
        is_ready = False
        if phase in ("Running", "Ready") and has_password:
            service_name = f"vdi-{username}-{project}"
            hostname = f"{service_name}.jupyterhub.svc.cluster.local"

            service_ready = False
            try:
                v1 = client.CoreV1Api()
                endpoints = v1.read_namespaced_endpoints(
                    name=service_name,
                    namespace="jupyterhub"
                )
                if endpoints.subsets:
                    for subset in endpoints.subsets:
                        if subset.addresses:
                            service_ready = True
                            break
            except Exception as e:
                print(f"Error checking endpoint readiness: {e}", flush=True)

            if service_ready:
                try:
                    with socket.create_connection((hostname, 3389), timeout=2):
                        is_ready = True
                except Exception as probe_err:
                    print(f"TCP readiness probe failed: {probe_err}", flush=True)

        return {
            "phase": phase,
            "has_password": has_password,
            "is_ready": is_ready,
            "name": instance_name
        }
    except client.exceptions.ApiException as e:
        if e.status == 404:
            return JSONResponse({"error": "VDI instance not found"}, status_code=404)
        return JSONResponse({"error": f"Failed to get VDI status: {e.reason}"}, status_code=e.status)


@app.get("/api/vdi/connect/{username}/{project}")
async def connect_to_vdi(username: str, project: str, request: Request, user=Depends(require_user)):
    """ Generate Guacamole token and redirect to VDI
    """
    current_user = user.get("preferred_username")
    if current_user != username:
        raise HTTPException(status_code=403, detail="Access denied")

    # Build connections for this user
    all_connections = _build_connections_for_user(username)
    print(f"All connections for {username}: {list(all_connections.keys())}", flush=True)

    project_connections = {
        conn_id: conn_data
        for conn_id, conn_data in all_connections.items()
        if conn_id.startswith(f"{project}-")
    }
    print(f"Project connections for {project}: {list(project_connections.keys())}", flush=True)

    if not project_connections:
        raise HTTPException(status_code=404, detail=f"No VDI connection available for project {project}")

    # Generate auth token
    expiry_ms = int(time.time() * 1000) + 60_000
    data = {
        "username": username,
        "expires": expiry_ms,
        "connections": project_connections,
    }
    print(f"Guacamole token data: username={username}, connections={list(data['connections'].keys())}", flush=True)

    auth_token = await _get_guac_auth_token(data)
    guacamole_url = build_service_url("guacamole")
    redirect_url = f"{guacamole_url}/guacamole/?token={auth_token}"
    print(f"Redirecting to: {redirect_url}", flush=True)

    return RedirectResponse(redirect_url)


@app.delete("/internal/vdi/{username}/{project}")
def delete_vdi_instance(username: str = Path(...), project: str = Path(...)):
    """ Function to delete a vdi instance.
    """
    instance_name = f"{username}-{project}".lower()
    try:
        k8s_api.delete_namespaced_custom_object(
            group="karectl.io",
            version="v1alpha1",
            namespace="jupyterhub",
            plural="vdiinstances",
            name=instance_name,
            body=client.V1DeleteOptions()
        )
        return {"status": "deleted", "instance": instance_name}
    except client.exceptions.ApiException as e:
        return JSONResponse({"error": f"Failed to delete VDIInstance: {e.reason}"}, status_code=e.status)

@app.post("/shutdown-vdi")
async def shutdown_vdi(request: Request, user=Depends(require_user)):
    """ Shutdown a running VDI
    """
    form = await request.form()
    project = form.get("project")
    username = user["preferred_username"]
    delete_vdi_instance(username=username, project=project)
    return RedirectResponse("/vdi", status_code=302)

@app.get("/vdi", response_class=HTMLResponse)
def get_vdi_instances(request: Request, user=Depends(require_user)):
    """ Show user's VDI instances with shutdown option
    """
    username = user["preferred_username"]
    
    try:
        # Get all VDI instances for this user
        vdi_instances = []
        crd = k8s_api.list_namespaced_custom_object(
            group="karectl.io", version="v1alpha1", namespace="jupyterhub", plural="vdiinstances"
        )
        
        for vdi in crd.get("items", []):
            spec = vdi.get("spec", {})
            status = vdi.get("status", {})
            metadata = vdi.get("metadata", {})
            
            if spec.get("user") == username:
                vdi_instances.append({
                    "name": metadata.get("name"),
                    "project": spec.get("project"),
                    "image": spec.get("image"),
                    "phase": status.get("phase", "Unknown"),
                    "created": metadata.get("creationTimestamp"),
                    "has_password": bool(status.get("password"))
                })
        
        return templates.TemplateResponse(
            "vdi.html",
            {"request": request, "user": user, "vdi_instances": vdi_instances}
        )
        
    except Exception as e:
        return templates.TemplateResponse(
            "error.html", 
            {"request": request, "error": f"Failed to fetch VDI instances: {e}"}
        )

@app.post("/api/vdi/refresh-token")
async def vdi_refresh_token(
    current_token: str = Query(...),
    refresh_token: str = Query(...),
    project: str = Query(...),
    user: str = Query(...)
):
    """ Refresh token specifically for VDI environments
    """
    try:
        # Verify current token is from the expected user
        try:
            decoded = jwt.decode(current_token, options={"verify_signature": False})
            token_user = decoded.get('preferred_username')
            if token_user != user:
                raise HTTPException(status_code=403, detail="Token user mismatch")
        except:
            pass
        
        # Use refresh token to get new access token
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(
                f"{internal_base}/protocol/openid-connect/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": os.environ["KEYCLOAK_CLIENT_ID"],
                    "client_secret": os.environ["KEYCLOAK_CLIENT_SECRET"],
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
        
        if response.status_code == 200:
            token_data = response.json()
            new_access_token = token_data["access_token"]
            new_refresh_token = token_data.get("refresh_token", refresh_token)
            
            return {
                "token": new_access_token,
                "refresh_token": new_refresh_token,
                "status": "refreshed",
                "expires_in": token_data.get("expires_in", 3600)
            }
        else:
            return JSONResponse({"error": "Token refresh failed"}, status_code=401)
            
    except Exception as e:
        print(f"VDI token refresh error: {e}", flush=True)
        return JSONResponse({"error": "Token refresh failed"}, status_code=401)

@app.get("/api/refresh-token")
async def refresh_token_api(
    current_token: str = Query(...),
    project: str = Query(...),
    user: str = Query(...)
):
    """ Refresh token for VDI users
    """
    try:
        decoded = jwt.decode(current_token, options={"verify_signature": False})
        exp = decoded.get('exp', 0)
        current_time = int(time.time())
        
        if exp - current_time > 300:  # Token valid for more than 5 minutes
            return {"token": current_token, "status": "valid"}
        
        return {"token": current_token, "status": "valid"}
        
    except Exception as e:
        return JSONResponse({"error": "Token refresh failed"}, status_code=401)

@app.get("/health")
async def health_check():
    """ Health end point if it is reachable.
    """
    return {"status": "healthy", "service": "karectl-backend"}
