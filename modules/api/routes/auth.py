import io
import base64
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from jose import JWTError, jwt as jose_jwt
from pydantic import BaseModel
from sqlalchemy.orm import Session

from modules.api.database import get_db
from modules.api.models import User
from modules.api.schemas import UserCreate, UserResponse, Token
from modules.api.auth import (
    hash_password, verify_password, validate_password,
    create_access_token, create_refresh_token,
    check_rate_limit, record_failed_attempt, clear_rate_limit,
    blacklist_token, set_auth_cookies, clear_auth_cookies,
    get_current_user, SECRET_KEY, ALGORITHM, ACCOUNT_LOCKOUT_MINUTES,
    _get_redis,
)

router = APIRouter()

GENERIC_AUTH_ERROR = "Invalid email or password"


# ─── Register ─────────────────────────────────────────────────────────

@router.post("/register", response_model=UserResponse)
def register(body: UserCreate, db: Session = Depends(get_db)):
    """Register a new user account.

    The first registered user is automatically promoted to admin.
    Password requirements: minimum 8 characters, must contain uppercase letter.
    """
    pw_error = validate_password(body.password)
    if pw_error:
        raise HTTPException(status_code=400, detail=pw_error)

    if db.query(User).filter(User.email == body.email.lower()).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    is_first_user = db.query(User).count() == 0
    user = User(
        email=body.email.lower().strip(),
        hashed_password=hash_password(body.password),
        is_admin=is_first_user,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# ─── Login (with optional 2FA) ───────────────────────────────────────

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 1800
    requires_2fa: bool = False


class TwoFactorVerifyRequest(BaseModel):
    totp_token: str  # temporary token from login step 1
    code: str        # 6-digit TOTP code


@router.post("/login", response_model=LoginResponse)
def login(body: UserCreate, response: Response, db: Session = Depends(get_db)):
    """Authenticate and get JWT access token.

    If 2FA is enabled, returns a temporary token with requires_2fa=true.
    Use /verify-2fa with the temporary token and TOTP code to complete login.
    """
    email = body.email.lower().strip()

    if check_rate_limit(email):
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again in 15 minutes.")

    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(body.password, user.hashed_password):
        record_failed_attempt(email)
        if user:
            user.failed_attempts = (user.failed_attempts or 0) + 1
            if user.failed_attempts >= 5:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=ACCOUNT_LOCKOUT_MINUTES)
            db.commit()
        raise HTTPException(status_code=401, detail=GENERIC_AUTH_ERROR)

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")

    if user.locked_until and user.locked_until.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
        raise HTTPException(status_code=423, detail="Account locked. Try again later.")

    # If 2FA is enabled, return a temporary TOTP token instead of real tokens
    if user.totp_enabled and user.totp_secret:
        totp_token = _create_totp_pending_token(user.id)
        return LoginResponse(
            access_token=totp_token,
            token_type="totp_pending",
            expires_in=300,
            requires_2fa=True,
        )

    # No 2FA — issue tokens directly
    return _complete_login(user, response, db)


@router.post("/verify-2fa", response_model=LoginResponse)
def verify_2fa(body: TwoFactorVerifyRequest, response: Response, db: Session = Depends(get_db)):
    """Step 2 of 2FA login: verify TOTP code and issue real tokens."""
    user_id = _verify_totp_pending_token(body.totp_token)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired 2FA session")

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.totp_enabled or not user.totp_secret:
        raise HTTPException(status_code=401, detail="Invalid 2FA session")

    import pyotp
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(status_code=401, detail="Invalid 2FA code")

    # Consume the pending token
    _consume_totp_pending_token(body.totp_token)

    return _complete_login(user, response, db)


def _complete_login(user: User, response: Response, db: Session) -> LoginResponse:
    """Issue access + refresh tokens after all auth checks pass."""
    user.failed_attempts = 0
    user.locked_until = None
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    clear_rate_limit(user.email)

    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)
    set_auth_cookies(response, access_token, refresh_token)

    return LoginResponse(access_token=access_token)


# ─── TOTP pending tokens (Redis, 5 min TTL) ──────────────────────────

def _create_totp_pending_token(user_id: str) -> str:
    import secrets
    token = secrets.token_urlsafe(32)
    r = _get_redis()
    if r:
        r.setex(f"totp:pending:{token}", 300, user_id)
    return token


def _verify_totp_pending_token(token: str) -> str | None:
    r = _get_redis()
    if not r:
        return None
    val = r.get(f"totp:pending:{token}")
    if not val:
        return None
    return val.decode() if isinstance(val, bytes) else val


def _consume_totp_pending_token(token: str):
    r = _get_redis()
    if r:
        r.delete(f"totp:pending:{token}")


# ─── 2FA setup endpoints ─────────────────────────────────────────────

class Enable2FAResponse(BaseModel):
    secret: str
    otpauth_url: str
    qr_code_url: str


@router.post("/2fa/setup", response_model=Enable2FAResponse)
def setup_2fa(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Generate a TOTP secret and QR code URL. Does NOT enable 2FA yet — call /2fa/enable with a valid code."""
    import pyotp

    if user.totp_enabled:
        raise HTTPException(status_code=400, detail="2FA is already enabled")

    secret = pyotp.random_base32()
    user.totp_secret = secret
    db.commit()

    totp = pyotp.TOTP(secret)
    otpauth_url = totp.provisioning_uri(name=user.email, issuer_name="Security Scanner")

    return Enable2FAResponse(
        secret=secret,
        otpauth_url=otpauth_url,
        qr_code_url=f"/api/auth/2fa/qrcode",
    )


@router.get("/2fa/qrcode")
def get_2fa_qrcode(user: User = Depends(get_current_user)):
    """Return QR code image for the TOTP secret."""
    if not user.totp_secret:
        raise HTTPException(status_code=400, detail="Run /2fa/setup first")

    import pyotp
    import qrcode

    totp = pyotp.TOTP(user.totp_secret)
    otpauth_url = totp.provisioning_uri(name=user.email, issuer_name="Security Scanner")

    qr = qrcode.QRCode(version=1, box_size=6, border=2)
    qr.add_data(otpauth_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


class Verify2FACode(BaseModel):
    code: str


@router.post("/2fa/enable")
def enable_2fa(body: Verify2FACode, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Verify a TOTP code and enable 2FA. Must call /2fa/setup first."""
    if user.totp_enabled:
        raise HTTPException(status_code=400, detail="2FA is already enabled")
    if not user.totp_secret:
        raise HTTPException(status_code=400, detail="Run /2fa/setup first")

    import pyotp
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid code. Make sure your authenticator app is synced.")

    user.totp_enabled = True
    db.commit()
    return {"status": "2FA enabled"}


@router.post("/2fa/disable")
def disable_2fa(
    body: Verify2FACode,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Disable 2FA. Requires a valid TOTP code for confirmation."""
    if not user.totp_enabled:
        raise HTTPException(status_code=400, detail="2FA is not enabled")

    import pyotp
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid code")

    user.totp_enabled = False
    user.totp_secret = None
    db.commit()
    return {"status": "2FA disabled"}


# ─── Refresh ──────────────────────────────────────────────────────────

@router.post("/refresh", response_model=LoginResponse)
def refresh_token(request: Request, response: Response, db: Session = Depends(get_db)):
    """Refresh an expired access token using the refresh token cookie."""
    raw_token = request.cookies.get("refresh_token")
    if not raw_token:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            raw_token = auth[7:]
    if not raw_token:
        raise HTTPException(status_code=401, detail="No refresh token")

    try:
        payload = jose_jwt.decode(raw_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        token_type = payload.get("type")
        if token_type != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid token")

    new_access = create_access_token(user.id)
    new_refresh = create_refresh_token(user.id)
    blacklist_token(raw_token)
    set_auth_cookies(response, new_access, new_refresh)
    return LoginResponse(access_token=new_access)


# ─── Logout ───────────────────────────────────────────────────────────

@router.post("/logout")
def logout(request: Request, response: Response):
    access = request.cookies.get("access_token")
    if not access:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            access = auth[7:]
    if access:
        blacklist_token(access)
    refresh = request.cookies.get("refresh_token")
    if refresh:
        blacklist_token(refresh)
    clear_auth_cookies(response)
    return {"status": "logged out"}


# ─── Current user info ────────────────────────────────────────────────

@router.get("/me", response_model=UserResponse)
def me(user: User = Depends(get_current_user)):
    return user


# ─── Change password ──────────────────────────────────────────────────

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.post("/change-password")
def change_password(
    body: ChangePasswordRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(body.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    pw_error = validate_password(body.new_password)
    if pw_error:
        raise HTTPException(status_code=400, detail=pw_error)
    user.hashed_password = hash_password(body.new_password)
    db.commit()
    return {"status": "password changed"}


# ─── User management (admin) ─────────────────────────────────────────

class UserUpdateRequest(BaseModel):
    email: str | None = None
    plan: str | None = None
    is_active: bool | None = None
    is_admin: bool | None = None


class AdminCreateUserRequest(BaseModel):
    email: str
    password: str
    plan: str = "free"


@router.get("/users", response_model=list[UserResponse])
def list_users(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """List all users (admin only)."""
    _require_admin(user, db)
    return db.query(User).order_by(User.created_at.asc()).all()


@router.post("/users", response_model=UserResponse)
def admin_create_user(body: AdminCreateUserRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_admin(user, db)
    pw_error = validate_password(body.password)
    if pw_error:
        raise HTTPException(status_code=400, detail=pw_error)
    if db.query(User).filter(User.email == body.email.lower()).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    new_user = User(email=body.email.lower().strip(), hashed_password=hash_password(body.password), plan=body.plan)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@router.patch("/users/{user_id}", response_model=UserResponse)
def admin_update_user(user_id: str, body: UserUpdateRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_admin(user, db)
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if body.email is not None:
        existing = db.query(User).filter(User.email == body.email.lower(), User.id != user_id).first()
        if existing:
            raise HTTPException(status_code=400, detail="Email already in use")
        target.email = body.email.lower().strip()
    if body.plan is not None:
        target.plan = body.plan
    if body.is_active is not None:
        target.is_active = body.is_active
    if body.is_admin is not None:
        target.is_admin = body.is_admin
    db.commit()
    db.refresh(target)
    return target


@router.delete("/users/{user_id}")
def admin_delete_user(user_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_admin(user, db)
    if user_id == user.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(target)
    db.commit()
    return {"status": "deleted"}


@router.post("/users/{user_id}/reset-password")
def admin_reset_password(user_id: str, body: ChangePasswordRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_admin(user, db)
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    pw_error = validate_password(body.new_password)
    if pw_error:
        raise HTTPException(status_code=400, detail=pw_error)
    target.hashed_password = hash_password(body.new_password)
    target.failed_attempts = 0
    target.locked_until = None
    db.commit()
    return {"status": "password reset"}


@router.post("/users/{user_id}/unlock")
def admin_unlock_user(user_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_admin(user, db)
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    target.failed_attempts = 0
    target.locked_until = None
    clear_rate_limit(target.email)
    db.commit()
    return {"status": "unlocked"}


@router.post("/users/{user_id}/disable-2fa")
def admin_disable_2fa(user_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Admin: force-disable 2FA for a user (e.g. if they lost their device)."""
    _require_admin(user, db)
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    target.totp_enabled = False
    target.totp_secret = None
    db.commit()
    return {"status": "2FA disabled"}


def _require_admin(user: User, db: Session):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
