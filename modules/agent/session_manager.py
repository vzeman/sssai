"""
Session manager for authenticated scanning.

Handles authentication against target applications and maintains session state
(cookies, headers) across all tool calls in a scan. Credentials are never
logged or stored in reports.

Supported auth types:
  form_login   — POST login form and collect session cookies
  bearer_token — Use a pre-issued Bearer token
  basic_auth   — HTTP Basic authentication
  oauth2       — OAuth2 client_credentials or password grant
  cookie       — Pre-supplied cookies
  api_key      — API key via header or query parameter
"""

import base64
import logging
import re
import time

import httpx

log = logging.getLogger(__name__)

SUPPORTED_AUTH_TYPES = frozenset(
    {"form_login", "bearer_token", "basic_auth", "oauth2", "cookie", "api_key"}
)


class SessionManager:
    """Manages authentication state for a single scan.

    Call ``authenticate()`` once at scan start.  Then inject session headers /
    cookies into every outbound HTTP request via ``get_headers()`` /
    ``get_cookies()``.  Use ``get_curl_flags()`` to build CLI tool invocations
    that carry the session.
    """

    def __init__(self, auth_config: dict):
        self.auth_type: str = auth_config.get("type", "")
        self._config: dict = dict(auth_config)
        self._session_cookies: dict[str, str] = {}
        self._session_headers: dict[str, str] = {}
        self._authenticated: bool = False
        self._auth_time: float | None = None
        self._token_expiry: float | None = None

    # ── Public API ──────────────────────────────────────────────────────────

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    def authenticate(self) -> dict:
        """Perform authentication and return a status dict (no credentials included)."""
        if self.auth_type not in SUPPORTED_AUTH_TYPES:
            return {
                "success": False,
                "error": (
                    f"Unsupported auth type: '{self.auth_type}'. "
                    f"Supported: {sorted(SUPPORTED_AUTH_TYPES)}"
                ),
            }
        try:
            method = getattr(self, f"_do_{self.auth_type}")
            return method()
        except Exception as exc:
            log.error("SessionManager.authenticate failed (%s): %s", self.auth_type, exc)
            return {"success": False, "error": str(exc)}

    def get_headers(self) -> dict[str, str]:
        """Return session headers to inject into HTTP requests."""
        return dict(self._session_headers)

    def get_cookies(self) -> dict[str, str]:
        """Return session cookies to inject into HTTP requests."""
        return dict(self._session_cookies)

    def get_cookie_header(self) -> str:
        """Return cookies formatted as a ``Cookie:`` header value."""
        return "; ".join(f"{k}={v}" for k, v in self._session_cookies.items())

    def get_curl_flags(self) -> str:
        """Return curl flags that carry the current session (for CLI tool invocations).

        Example result:
          -H 'Authorization: Bearer eyJ...' -b 'session=abc123; csrf=xyz'
        """
        flags: list[str] = []
        for header_name, header_value in self._session_headers.items():
            # Sanitize single-quotes inside values to avoid shell injection
            safe_value = header_value.replace("'", "'\\''")
            flags.append(f"-H '{header_name}: {safe_value}'")
        if self._session_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self._session_cookies.items())
            safe_cookie = cookie_str.replace("'", "'\\''")
            flags.append(f"-b '{safe_cookie}'")
        return " ".join(flags)

    def get_session_info(self) -> dict:
        """Return session metadata (no sensitive values)."""
        return {
            "auth_type": self.auth_type,
            "authenticated": self._authenticated,
            "auth_time": self._auth_time,
            "token_expiry": self._token_expiry,
            "has_cookies": bool(self._session_cookies),
            "cookie_names": list(self._session_cookies.keys()),
            "has_auth_headers": bool(self._session_headers),
            "auth_header_names": list(self._session_headers.keys()),
            "session_valid": self.is_session_valid(),
        }

    def is_session_valid(self) -> bool:
        """Return True if the session is authenticated and not expired."""
        if not self._authenticated:
            return False
        if self._token_expiry is not None and time.time() > self._token_expiry:
            return False
        return True

    # ── Auth type implementations ────────────────────────────────────────────

    def _do_form_login(self) -> dict:
        cfg = self._config
        login_url: str = cfg.get("login_url", "")
        username_field: str = cfg.get("username_field", "username")
        password_field: str = cfg.get("password_field", "password")
        credentials: dict = cfg.get("credentials", {})
        success_indicator: str = cfg.get("success_indicator", "")
        extra_fields: dict = cfg.get("extra_fields", {})
        csrf_field: str | None = cfg.get("csrf_field")

        if not login_url:
            return {"success": False, "error": "login_url is required for form_login"}
        if not credentials:
            return {"success": False, "error": "credentials dict is required for form_login"}

        # Build form payload — credentials keys may match field names or use
        # generic "username"/"password" keys.
        form_data: dict = {
            username_field: credentials.get(username_field, credentials.get("username", "")),
            password_field: credentials.get(password_field, credentials.get("password", "")),
        }
        form_data.update(extra_fields)

        with httpx.Client(follow_redirects=True, timeout=30) as client:
            # GET the login page first — collects pre-session cookies and CSRF
            try:
                init_resp = client.get(login_url)
                for k, v in init_resp.cookies.items():
                    self._session_cookies[k] = v

                if csrf_field:
                    csrf_match = re.search(
                        rf'name=["\']?{re.escape(csrf_field)}["\']?\s*'
                        rf'(?:value=["\']?([^"\'>\s]+)["\']?)?',
                        init_resp.text,
                    )
                    if csrf_match and csrf_match.group(1):
                        form_data[csrf_field] = csrf_match.group(1)
            except Exception as exc:
                log.debug("form_login: GET %s failed (continuing): %s", login_url, exc)

            resp = client.post(login_url, data=form_data, cookies=self._session_cookies)

            # Determine success
            if success_indicator:
                success = (
                    success_indicator.lower() in resp.text.lower()
                    or success_indicator.lower() in str(resp.url).lower()
                )
            else:
                # Heuristic: not a 401/403, not redirected back to login page
                success = resp.status_code not in (401, 403) and (
                    "login" not in str(resp.url).lower()
                    or resp.status_code < 400
                )

            if success:
                for k, v in resp.cookies.items():
                    self._session_cookies[k] = v
                self._authenticated = True
                self._auth_time = time.time()
                return {
                    "success": True,
                    "auth_type": "form_login",
                    "cookies_obtained": list(self._session_cookies.keys()),
                    "final_url": str(resp.url),
                    "status_code": resp.status_code,
                }
            else:
                return {
                    "success": False,
                    "error": (
                        f"Login did not succeed "
                        f"(status={resp.status_code}, url={resp.url})"
                    ),
                    "status_code": resp.status_code,
                }

    def _do_bearer_token(self) -> dict:
        token: str = self._config.get("token", "")
        if not token:
            return {"success": False, "error": "token is required for bearer_token auth"}
        self._session_headers["Authorization"] = f"Bearer {token}"
        self._authenticated = True
        self._auth_time = time.time()
        expires_at = self._config.get("expires_at")
        if expires_at:
            self._token_expiry = float(expires_at)
        return {
            "success": True,
            "auth_type": "bearer_token",
            "header_set": "Authorization: Bearer <token>",
        }

    def _do_basic_auth(self) -> dict:
        credentials: dict = self._config.get("credentials", {})
        username: str = credentials.get("username", "")
        password: str = credentials.get("password", "")
        if not username:
            return {
                "success": False,
                "error": "credentials.username is required for basic_auth",
            }
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
        self._session_headers["Authorization"] = f"Basic {encoded}"
        self._authenticated = True
        self._auth_time = time.time()
        return {
            "success": True,
            "auth_type": "basic_auth",
            "header_set": "Authorization: Basic <encoded>",
        }

    def _do_oauth2(self) -> dict:
        cfg = self._config
        token_url: str = cfg.get("token_url", "")
        client_id: str = cfg.get("client_id", "")
        client_secret: str = cfg.get("client_secret", "")
        scope: str = cfg.get("scope", "")
        grant_type: str = cfg.get("grant_type", "client_credentials")
        credentials: dict = cfg.get("credentials", {})

        if not token_url:
            return {"success": False, "error": "token_url is required for oauth2"}
        if not client_id:
            return {"success": False, "error": "client_id is required for oauth2"}

        payload: dict = {
            "grant_type": grant_type,
            "client_id": client_id,
            "client_secret": client_secret,
        }
        if scope:
            payload["scope"] = scope
        if grant_type == "password" and credentials:
            payload["username"] = credentials.get("username", "")
            payload["password"] = credentials.get("password", "")

        with httpx.Client(timeout=30) as client:
            resp = client.post(token_url, data=payload)

        if resp.status_code == 200:
            data = resp.json()
            token = data.get("access_token", "")
            if not token:
                return {"success": False, "error": "No access_token in OAuth2 response"}
            self._session_headers["Authorization"] = f"Bearer {token}"
            self._authenticated = True
            self._auth_time = time.time()
            expires_in = data.get("expires_in")
            if expires_in:
                self._token_expiry = time.time() + int(expires_in)
            return {
                "success": True,
                "auth_type": "oauth2",
                "token_type": data.get("token_type", "Bearer"),
                "expires_in": expires_in,
                "scope": data.get("scope", scope),
            }
        return {
            "success": False,
            "error": (
                f"OAuth2 token request failed "
                f"(status={resp.status_code}): {resp.text[:300]}"
            ),
        }

    def _do_cookie(self) -> dict:
        cookies: dict = self._config.get("cookies", {})
        cookie_string: str = self._config.get("cookie_string", "")

        if cookie_string:
            for part in cookie_string.split(";"):
                part = part.strip()
                if "=" in part:
                    k, _, v = part.partition("=")
                    self._session_cookies[k.strip()] = v.strip()
        elif cookies:
            self._session_cookies.update(cookies)
        else:
            return {
                "success": False,
                "error": "Either 'cookies' dict or 'cookie_string' is required for cookie auth",
            }

        self._authenticated = True
        self._auth_time = time.time()
        return {
            "success": True,
            "auth_type": "cookie",
            "cookies_set": list(self._session_cookies.keys()),
        }

    def _do_api_key(self) -> dict:
        cfg = self._config
        key: str = cfg.get("key", "")
        header_name: str = cfg.get("header_name", "X-API-Key")
        query_param: str = cfg.get("query_param", "")

        if not key:
            return {"success": False, "error": "key is required for api_key auth"}

        if query_param:
            # Store for use by URL builders; not a header
            self._config["_query_param_name"] = query_param
            self._config["_query_param_value"] = key
            header_info = f"?{query_param}=<key> (query parameter)"
        else:
            self._session_headers[header_name] = key
            header_info = f"{header_name}: <key>"

        self._authenticated = True
        self._auth_time = time.time()
        return {
            "success": True,
            "auth_type": "api_key",
            "auth_method": header_info,
        }
