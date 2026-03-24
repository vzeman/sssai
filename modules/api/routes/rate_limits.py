"""
Admin routes for rate limiting management and DDoS protection tuning.
"""

from fastapi import APIRouter, Depends, HTTPException
from modules.api.auth import get_current_user
from modules.api.models import User
from modules.api.rate_limiter import get_rate_limiter, RateLimitAdmin

router = APIRouter(prefix="/admin/rate-limits", tags=["admin", "rate-limits"])


@router.get("/status/{identifier}")
async def get_rate_limit_status(
    identifier: str,
    user: User = Depends(get_current_user)
):
    """
    Get rate limit status for an identifier (user ID or IP).
    
    Admin only endpoint.
    """
    # Verify user is admin (can be enhanced with role-based access)
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    admin = RateLimitAdmin()
    status = admin.get_status(identifier)
    return status


@router.get("/locked-out")
async def list_locked_out_identifiers(
    user: User = Depends(get_current_user)
):
    """
    List all identifiers currently locked out.
    
    Admin only endpoint.
    """
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    admin = RateLimitAdmin()
    locked_out = admin.list_locked_out()
    return {
        "count": len(locked_out),
        "identifiers": locked_out
    }


@router.post("/unlock/{identifier}")
async def unlock_identifier(
    identifier: str,
    user: User = Depends(get_current_user)
):
    """
    Unlock an identifier (remove rate limit lockout).
    
    Admin only endpoint.
    """
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    admin = RateLimitAdmin()
    admin.unlock(identifier)
    return {
        "success": True,
        "message": f"Unlocked {identifier}"
    }


@router.put("/config")
async def update_rate_limit_config(
    requests_per_minute: int = 60,
    requests_per_hour: int = 1000,
    user: User = Depends(get_current_user)
):
    """
    Update global rate limit configuration.
    
    Admin only endpoint.
    """
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    admin = RateLimitAdmin()
    admin.update_config(
        requests_per_minute=requests_per_minute,
        requests_per_hour=requests_per_hour
    )
    
    limiter = get_rate_limiter()
    return {
        "success": True,
        "config": {
            "requests_per_minute": limiter.config.requests_per_minute,
            "requests_per_hour": limiter.config.requests_per_hour,
            "burst_limit": limiter.config.burst_limit,
            "lockout_threshold": limiter.config.lockout_threshold,
        }
    }


@router.get("/config")
async def get_rate_limit_config(
    user: User = Depends(get_current_user)
):
    """
    Get current rate limit configuration.
    """
    limiter = get_rate_limiter()
    return {
        "requests_per_minute": limiter.config.requests_per_minute,
        "requests_per_hour": limiter.config.requests_per_hour,
        "burst_limit": limiter.config.burst_limit,
        "burst_window_seconds": limiter.config.burst_window_seconds,
        "lockout_threshold": limiter.config.lockout_threshold,
        "lockout_duration_seconds": limiter.config.lockout_duration_seconds,
    }


def is_admin(user: User) -> bool:
    """Check if user has admin privileges."""
    return user.is_admin
