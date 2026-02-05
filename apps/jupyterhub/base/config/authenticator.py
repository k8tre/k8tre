# Custom JWT Authenticator that bypasses headers

c.JupyterHub.log_level = 'DEBUG'
from jupyterhub.auth import Authenticator
import jwt
import urllib.parse
import requests
import os, hmac, hashlib, time


AUTH_SIG_SECRET = os.environ.get("AUTH_SIG_SECRET", "change-me")
AUTH_SIG_TTL = int(os.environ.get("AUTH_SIG_TTL", "60"))

def _valid_signed_headers(user, project, stamp, sig, aud):
    try:
        # 1) TTL / replay window
        now = int(time.time())
        ts = int(stamp)
        if abs(now - ts) > AUTH_SIG_TTL:
            return False

        # 2) audience must be jupyterhub
        if aud != "jupyterhub":
            return False

        # 3) HMAC
        payload = f"{user}|{project}|{aud}|{stamp}".encode()
        expect = hmac.new(AUTH_SIG_SECRET.encode(), payload, hashlib.sha256).hexdigest()
        # constant-time compare
        return hmac.compare_digest(expect, sig)
    except Exception:
        return False

class JWTDirectAuthenticator(Authenticator):
    """ Custom authenticator that works with nginx-ingress auth validation
        Headers are set by your backend after JWT validation
    """

    async def authenticate(self, handler, data):
        """ This method is called for every login attempt
        """
        self.log.info("=== JWT DIRECT AUTHENTICATION START ===")
        self.log.info(f"Request URL: {handler.request.uri}")

        # Get all headers for debugging
        headers = dict(handler.request.headers)
        self.log.info("All headers received:")
        for name, value in headers.items():
            if any(keyword in name.lower() for keyword in ['auth', 'user', 'remote']):
                self.log.info(f"  {name}: {value}")

        # Get PVC from query
        try:
            pvc_param = handler.get_argument('pvc', None)
            if pvc_param:
                self.log.info(f"Notebook PVC from query: {pvc_param}")
        except:
            pvc_param = None

        # Method 1: Check headers set by your backend (primary method)
        remote_user = headers.get('Remote-User', '').strip()
        x_auth_user = headers.get('X-Auth-User', '').strip()
        user_hdr = remote_user or x_auth_user

        stamp = headers.get('X-Auth-Stamp', '')
        sig   = headers.get('X-Auth-Signature', '')
        aud   = headers.get('X-Auth-Audience', '')
        proj  = headers.get('X-Auth-Project', '')

        if user_hdr:
            if _valid_signed_headers(user_hdr, proj, stamp, sig, aud):
                auth_email = headers.get('X-Auth-Email', '')

                # Making username project scoped to session leakage.
                if proj:
                    scoped_username = f"{user_hdr}-{proj}"
                    self.log.info(f"Using project-scoped username: '{scoped_username}'")
                else:
                    scoped_username = user_hdr
                    self.log.warning(f"No project available, using username without scope: '{scoped_username}'")

                return {
                    'name': scoped_username,
                    'auth_model': {
                        'email': auth_email,
                        'auth_method': 'signed_headers',
                        'project': proj,
                        'base_user': user_hdr,
                        'notebook_pvc': pvc_param
                    }
                }
            else:
                self.log.warning("User header present but signed headers invalid/missing; will try token fallbacks")
        
        # Method 2: Fallback to JWT token in query parameters
        try:
            token_param = handler.get_argument('token', None)
            project_param = handler.get_argument('project', None)
            pvc_param = handler.get_argument('pvc', None)

            if token_param:
                self.log.info("Found token in query parameters, attempting decode...")
                # Decode without signature verification (backend already validated)
                decoded = jwt.decode(token_param, options={"verify_signature": False})
                username = decoded.get('preferred_username')
                email = decoded.get('email')

                if username:
                    if project_param:
                        scoped_username = f"{username}-{project_param}"
                        self.log.info(f"Using project-scoped username: '{scoped_username}'")
                    else:
                        scoped_username = username
                        self.log.warning(f"No project available, using username without scope: '{scoped_username}'")

                    if pvc_param:
                        self.log.info(f"Notebook PVC from query: {pvc_param}")

                    return {
                        'name': scoped_username,
                        'auth_model': {
                            'email': email,
                            'auth_method': 'jwt_query_param',
                            'project': project_param,
                            'base_user': username,
                            'notebook_pvc': pvc_param
                        }
                    }
        except Exception as e:
            self.log.error(f"JWT query param decode error: {e}")
        
        # Method 3: Check Authorization header as fallback
        auth_header = headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ', 1)[1]
            self.log.info("Found Bearer token in Authorization header")

            # Get project from params or X-Auth-Project header
            try:
                project_param = handler.get_argument('project', None)
            except:
                project_param = None
            if not project_param:
                project_param = proj

            try:
                decoded = jwt.decode(token, options={"verify_signature": False})
                username = decoded.get('preferred_username')
                email = decoded.get('email')

                if username:
                    # Making username project scoped to prevent session leakage.
                    if project_param:
                        scoped_username = f"{username}-{project_param}"
                        self.log.info(f"Using project-scoped username: '{scoped_username}'")
                    else:
                        scoped_username = username
                        self.log.warning(f"No project available, using username without scope: '{scoped_username}'")

                    return {
                        'name': scoped_username,
                        'auth_model': {
                            'email': email,
                            'auth_method': 'jwt_auth_header',
                            'project': project_param,
                            'base_user': username,
                            'notebook_pvc': pvc_param
                        }
                    }
            except Exception as e:
                self.log.error(f"Authorization header JWT decode error: {e}")
        
        self.log.error("JWT DIRECT AUTHENTICATION FAILED")
        self.log.error("No valid authentication method found")
        return None
    
    def get_handlers(self, app):
        """
        Override to prevent default login form
        This forces all authentication to go through our authenticate() method
        """
        from jupyterhub.handlers import BaseHandler

        class AutoLoginHandler(BaseHandler):
            """ Auto-login handler that immediately triggers authentication
            """
            async def get(self):
                auto = self.get_argument('auto', None)

                if auto:
                    self.log.info("Auto-login triggered, authenticating immediately...")
                    # Trigger authentication
                    user = await self.login_user()
                    if user:
                        self.log.info(f"Auto-login successful for {user.name}")
                        self.redirect(self.hub.base_url + 'spawn')
                    else:
                        self.log.error("Auto-login failed, showing error")
                        self.redirect(self.hub.base_url + 'login')
                else:
                    user = await self.login_user()
                    if user:
                        self.redirect(self.hub.base_url + 'home')

        self.log.info("Auto-login enabled")
        return [
            (r'/login', AutoLoginHandler),
        ]

# Configure the authenticator
c.JupyterHub.authenticator_class = JWTDirectAuthenticator
c.JupyterHub.admin_access = True
c.JupyterHub.shutdown_on_logout = False
c.Authenticator.enable_auth_state = True
c.Authenticator.admin_users = ["admin"]
c.Authenticator.allow_all = True
c.Authenticator.auto_login = True

# CRITICAL: Ensure user isolation
c.JupyterHub.allow_named_servers = False
c.JupyterHub.redirect_to_server = False
c.Authenticator.refresh_pre_spawn = True
c.JupyterHub.cookie_max_age_days = 0.1