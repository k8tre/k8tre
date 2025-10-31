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
                self.log.info(f"Signed headers valid for user '{user_hdr}', project '{proj}', aud '{aud}'")
                return {
                    'name': user_hdr,
                    'auth_model': {
                        'email': auth_email,
                        'auth_method': 'signed_headers'
                    }
                }
            else:
                self.log.warning("User header present but signed headers invalid/missing; will try token fallbacks")
        
        # Method 2: Fallback to JWT token in query parameters
        try:
            token_param = handler.get_argument('token', None)
            if token_param:
                self.log.info("Found token in query parameters, attempting decode...")
                # Decode without signature verification (backend already validated)
                decoded = jwt.decode(token_param, options={"verify_signature": False})
                username = decoded.get('preferred_username')
                email = decoded.get('email')
                
                if username:
                    self.log.info(f"Extracted username from query token: '{username}' with email: '{email}'")
                    return {
                        'name': username,
                        'auth_model': {
                            'email': email,
                            'auth_method': 'jwt_query_param'
                        }
                    }
        except Exception as e:
            self.log.error(f"JWT query param decode error: {e}")
        
        # Method 3: Check Authorization header as fallback
        auth_header = headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ', 1)[1]
            self.log.info("Found Bearer token in Authorization header")
            
            try:
                decoded = jwt.decode(token, options={"verify_signature": False})
                username = decoded.get('preferred_username')
                email = decoded.get('email')
                
                if username:
                    self.log.info(f"Extracted username from Authorization header: '{username}' with email: '{email}'")
                    return {
                        'name': username,
                        'auth_model': {
                            'email': email,
                            'auth_method': 'jwt_auth_header'
                        }
                    }
            except Exception as e:
                self.log.error(f"Authorization header JWT decode error: {e}")
        
        self.log.error("JWT DIRECT AUTHENTICATION FAILED")
        self.log.error("No valid authentication method found")
        return None
    
    def get_handlers(self, app):
        """
        Override to prevent default login form handlers
        This forces all authentication to go through our authenticate() method
        """
        self.log.info("=== GETTING CUSTOM HANDLERS - No default login form ===")
        return []

# Configure the authenticator
c.JupyterHub.authenticator_class = JWTDirectAuthenticator
c.JupyterHub.admin_access = True
c.JupyterHub.shutdown_on_logout = True
c.Authenticator.enable_auth_state = True
c.Authenticator.admin_users = ["admin"]
c.Authenticator.allow_all = True
c.Authenticator.auto_login = True

# CRITICAL: Ensure user isolation
c.JupyterHub.allow_named_servers = False
c.JupyterHub.redirect_to_server = False
c.Authenticator.refresh_pre_spawn = True
c.JupyterHub.cookie_max_age_days = 0.1