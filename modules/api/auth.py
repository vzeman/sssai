import logging
import os
import re
import secrets
from datetime import datetime, timedelta, timezone

import redis as _redis
from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from modules.api.database import get_db
from modules.api.models import User

log = logging.getLogger(__name__)

# ─── Configuration ────────────────────────────────────────────────────
SECRET_KEY = os.getenv("JWT_SECRET", "")
if not SECRET_KEY or SECRET_KEY == "dev-secret-change-in-production":
    # In production this MUST be set. For local dev, generate a random one per boot.
    SECRET_KEY = secrets.token_urlsafe(64)
    log.warning("JWT_SECRET not set — generated ephemeral key. Set JWT_SECRET env var for persistence.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 hours
REFRESH_TOKEN_EXPIRE_DAYS = 30  # 30 days

_REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)

# ─── Rate limiting config ────────────────────────────────────────────
MAX_LOGIN_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 900  # 15 minutes
ACCOUNT_LOCKOUT_MINUTES = 30


# ─── Password hashing ────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ─── Password policy ─────────────────────────────────────────────────

def validate_password(password: str) -> str | None:
    """Returns error message if password is invalid, None if valid."""
    if len(password) < 8:
        return "Password must be at least 8 characters"
    if not re.search(r"[a-z]", password):
        return "Password must contain a lowercase letter"
    if not re.search(r"[A-Z]", password):
        return "Password must contain an uppercase letter"
    if not re.search(r"\d", password):
        return "Password must contain a digit"
    return None


# ─── Token generation ────────────────────────────────────────────────

def create_access_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": user_id, "exp": expire, "type": "access"},
        SECRET_KEY, algorithm=ALGORITHM,
    )


def create_refresh_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    jti = secrets.token_urlsafe(16)  # unique token ID for revocation
    return jwt.encode(
        {"sub": user_id, "exp": expire, "type": "refresh", "jti": jti},
        SECRET_KEY, algorithm=ALGORITHM,
    )


# ─── Token blacklist (Redis) ─────────────────────────────────────────

def _get_redis():
    try:
        return _redis.from_url(_REDIS_URL)
    except Exception:
        return None


def blacklist_token(token: str):
    """Add a token to the blacklist until it naturally expires."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti = payload.get("jti", "")
        exp = payload.get("exp", 0)
        ttl = max(int(exp - datetime.now(timezone.utc).timestamp()), 0)
        r = _get_redis()
        if r and jti:
            r.setex(f"token:blacklist:{jti}", ttl + 60, "1")
    except Exception:
        pass


def is_token_blacklisted(token: str) -> bool:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti = payload.get("jti")
        if not jti:
            return False
        r = _get_redis()
        if r:
            return r.exists(f"token:blacklist:{jti}") > 0
    except Exception:
        pass
    return False


# ─── Rate limiting ───────────────────────────────────────────────────

def check_rate_limit(email: str) -> bool:
    """Returns True if rate limited (too many attempts)."""
    try:
        r = _get_redis()
        if not r:
            return False
        key = f"auth:attempts:{email.lower()}"
        attempts = r.get(key)
        if attempts and int(attempts) >= MAX_LOGIN_ATTEMPTS:
            return True
    except Exception:
        pass
    return False


def record_failed_attempt(email: str):
    try:
        r = _get_redis()
        if not r:
            return
        key = f"auth:attempts:{email.lower()}"
        pipe = r.pipeline()
        pipe.incr(key)
        pipe.expire(key, RATE_LIMIT_WINDOW)
        pipe.execute()
    except Exception:
        pass


def clear_rate_limit(email: str):
    try:
        r = _get_redis()
        if r:
            r.delete(f"auth:attempts:{email.lower()}")
    except Exception:
        pass


# ─── Report access tokens (short-lived, single-use) ──────────────────

def create_report_token(user_id: str, scan_id: str, ttl: int = 300) -> str:
    """Create a 5-minute single-use token for HTML report viewing."""
    token_id = secrets.token_urlsafe(16)
    try:
        r = _get_redis()
        if r:
            r.setex(f"report:token:{token_id}", ttl, f"{user_id}:{scan_id}")
    except Exception:
        pass
    return token_id


def verify_report_token(token_id: str, scan_id: str) -> str | None:
    """Verify and consume a report token. Returns user_id or None."""
    try:
        r = _get_redis()
        if not r:
            return None
        key = f"report:token:{token_id}"
        value = r.get(key)
        if not value:
            return None
        r.delete(key)  # single-use
        val = value.decode() if isinstance(value, bytes) else value
        stored_user_id, stored_scan_id = val.split(":", 1)
        if stored_scan_id == scan_id:
            return stored_user_id
    except Exception:
        pass
    return None


# ─── Token validation / current user ─────────────────────────────────

def get_current_user(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    raw_token = None

    # Try Bearer header
    if creds:
        raw_token = creds.credentials
    # Fallback: cookie (for refresh-based flows)
    if not raw_token:
        raw_token = request.cookies.get("access_token")

    if not raw_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    try:
        payload = jwt.decode(raw_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        token_type = payload.get("type", "access")
        if token_type != "access":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    # Check blacklist
    if is_token_blacklisted(raw_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")
    return user


# ─── Cookie helpers ──────────────────────────────────────────────────

def set_auth_cookies(response: Response, access_token: str, refresh_token: str):
    """Set secure HttpOnly cookies for tokens."""
    response.set_cookie(
        key="access_token", value=access_token,
        httponly=True, samesite="strict", secure=False,  # set secure=True in production with HTTPS
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    response.set_cookie(
        key="refresh_token", value=refresh_token,
        httponly=True, samesite="strict", secure=False,
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        path="/api/auth",  # only sent to auth endpoints
    )


def clear_auth_cookies(response: Response):
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token", path="/api/auth")


# ─── Webhook API key authentication ──────────────────────────────────

def generate_api_key() -> tuple[str, str, str]:
    """Generate a webhook API key. Returns (plain_key, key_prefix, key_hash)."""
    raw = secrets.token_urlsafe(32)
    plain_key = f"whk_{raw}"
    key_prefix = plain_key[:12]
    key_hash = pwd_context.hash(plain_key)
    return plain_key, key_prefix, key_hash


def verify_api_key(plain_key: str, key_hash: str) -> bool:
    """Verify a plain API key against its stored hash."""
    return pwd_context.verify(plain_key, key_hash)


def get_webhook_user(
    request: Request,
    db: Session = Depends(get_db),
) -> tuple["User", "WebhookConfig"]:  # noqa: F821
    """Dependency: authenticate via X-API-Key header, return (user, webhook_config)."""
    from modules.api.models import WebhookConfig

    api_key = request.headers.get("X-API-Key", "")
    if not api_key or not api_key.startswith("whk_"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid API key. Use X-API-Key header with a webhook API key.",
        )

    key_prefix = api_key[:12]
    candidates = db.query(WebhookConfig).filter(
        WebhookConfig.key_prefix == key_prefix,
        WebhookConfig.is_active == True,  # noqa: E712
    ).all()

    for wh in candidates:
        if verify_api_key(api_key, wh.key_hash):
            user = db.query(User).filter(User.id == wh.user_id).first()
            if not user or not user.is_active:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")
            return user, wh

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
