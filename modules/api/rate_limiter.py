"""
Advanced rate limiting and DDoS protection for API endpoints.
Supports per-user, per-IP, and endpoint-specific rate limits with Redis backend.
"""

import os
import time
import logging
from typing import Optional, Dict, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import redis
import hashlib
from functools import wraps

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""
    # Requests per time window
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    
    # Burst protection
    burst_limit: int = 10  # Max requests in 10 seconds
    burst_window_seconds: int = 10
    
    # Lockout on abuse
    lockout_threshold: int = 5  # Lockout after N violations
    lockout_duration_seconds: int = 3600  # 1 hour
    
    # Cleanup
    cleanup_after_seconds: int = 86400  # 24 hours


class RateLimiter:
    """Redis-backed rate limiter with multiple strategies."""
    
    def __init__(self, redis_url: str = REDIS_URL, config: Optional[RateLimitConfig] = None):
        """
        Initialize rate limiter.
        
        Args:
            redis_url: Redis connection URL
            config: Rate limit configuration
        """
        self.redis = redis.from_url(redis_url)
        self.config = config or RateLimitConfig()
    
    def check_rate_limit(
        self,
        identifier: str,
        limit_type: str = "user",  # user, ip, endpoint
        requests_per_minute: Optional[int] = None,
        requests_per_hour: Optional[int] = None
    ) -> Tuple[bool, Dict[str, any]]:
        """
        Check if request is within rate limits.
        
        Args:
            identifier: Unique identifier (user_id, IP, endpoint)
            limit_type: Type of limit (user, ip, endpoint)
            requests_per_minute: Override default per-minute limit
            requests_per_hour: Override default per-hour limit
        
        Returns:
            Tuple of (allowed: bool, metadata: dict)
            metadata contains: limit_remaining, reset_at, etc.
        """
        now = time.time()
        per_minute = requests_per_minute or self.config.requests_per_minute
        per_hour = requests_per_hour or self.config.requests_per_hour
        
        # Check if locked out
        if self._is_locked_out(identifier):
            return False, {
                "reason": "rate_limit_exceeded",
                "lockout_until": self._get_lockout_until(identifier),
                "message": "Your access has been temporarily restricted due to excessive requests"
            }
        
        # Check minute limit
        minute_key = f"ratelimit:{limit_type}:{identifier}:minute"
        minute_count = self._increment_counter(minute_key, 60)
        minute_remaining = max(0, per_minute - minute_count)
        
        # Check hour limit
        hour_key = f"ratelimit:{limit_type}:{identifier}:hour"
        hour_count = self._increment_counter(hour_key, 3600)
        hour_remaining = max(0, per_hour - hour_count)
        
        # Check burst limit (anti-DoS)
        burst_allowed, burst_metadata = self._check_burst_limit(identifier)
        
        # Determine if allowed
        minute_ok = minute_count <= per_minute
        hour_ok = hour_count <= per_hour
        burst_ok = burst_allowed
        
        allowed = minute_ok and hour_ok and burst_ok
        
        # Violation tracking
        if not allowed:
            self._record_violation(identifier)
        
        # Build response metadata
        metadata = {
            "allowed": allowed,
            "requests_this_minute": minute_count,
            "minute_limit": per_minute,
            "minute_remaining": minute_remaining,
            "requests_this_hour": hour_count,
            "hour_limit": per_hour,
            "hour_remaining": hour_remaining,
            "minute_reset_at": now + (60 - (now % 60)),
            "hour_reset_at": now + (3600 - (now % 3600)),
        }
        
        if not burst_ok:
            metadata["burst_violation"] = True
            metadata["burst_message"] = burst_metadata.get("message")
        
        return allowed, metadata
    
    def _increment_counter(self, key: str, window_seconds: int) -> int:
        """Increment counter within time window."""
        pipe = self.redis.pipeline()
        pipe.incr(key)
        pipe.expire(key, window_seconds)
        results = pipe.execute()
        return results[0]
    
    def _check_burst_limit(self, identifier: str) -> Tuple[bool, Dict]:
        """Check burst limit (prevent DoS)."""
        burst_key = f"ratelimit:burst:{identifier}"
        
        now = time.time()
        burst_count = self.redis.incr(burst_key)
        
        if burst_count == 1:
            self.redis.expire(burst_key, self.config.burst_window_seconds)
        
        allowed = burst_count <= self.config.burst_limit
        
        return allowed, {
            "burst_count": burst_count,
            "burst_limit": self.config.burst_limit,
            "message": f"Too many requests in short time ({burst_count}/{self.config.burst_limit})"
        }
    
    def _record_violation(self, identifier: str) -> None:
        """Record rate limit violation for lockout tracking."""
        violation_key = f"ratelimit:violations:{identifier}"
        violations = self.redis.incr(violation_key)
        self.redis.expire(violation_key, self.config.lockout_duration_seconds)
        
        if violations >= self.config.lockout_threshold:
            self._apply_lockout(identifier)
            logger.warning(f"Rate limit lockout applied to {identifier} after {violations} violations")
    
    def _apply_lockout(self, identifier: str) -> None:
        """Apply temporary lockout to identifier."""
        lockout_key = f"ratelimit:lockout:{identifier}"
        self.redis.setex(
            lockout_key,
            self.config.lockout_duration_seconds,
            str(time.time())
        )
    
    def _is_locked_out(self, identifier: str) -> bool:
        """Check if identifier is locked out."""
        lockout_key = f"ratelimit:lockout:{identifier}"
        return self.redis.exists(lockout_key) > 0
    
    def _get_lockout_until(self, identifier: str) -> datetime:
        """Get lockout expiration time."""
        lockout_key = f"ratelimit:lockout:{identifier}"
        ttl = self.redis.ttl(lockout_key)
        if ttl > 0:
            return datetime.now() + timedelta(seconds=ttl)
        return datetime.now() + timedelta(seconds=self.config.lockout_duration_seconds)
    
    def get_status(self, identifier: str) -> Dict:
        """Get current rate limit status for identifier."""
        lockout_key = f"ratelimit:lockout:{identifier}"
        minute_key = f"ratelimit:user:{identifier}:minute"
        hour_key = f"ratelimit:user:{identifier}:hour"
        violation_key = f"ratelimit:violations:{identifier}"
        
        return {
            "identifier": identifier,
            "is_locked_out": self.redis.exists(lockout_key) > 0,
            "lockout_until": self._get_lockout_until(identifier).isoformat() if self.redis.exists(lockout_key) else None,
            "requests_minute": int(self.redis.get(minute_key) or 0),
            "requests_hour": int(self.redis.get(hour_key) or 0),
            "violations": int(self.redis.get(violation_key) or 0),
            "threshold": self.config.lockout_threshold,
        }
    
    def reset_identifier(self, identifier: str) -> None:
        """Reset rate limit counters for identifier."""
        patterns = [
            f"ratelimit:*:{identifier}:*",
            f"ratelimit:violations:{identifier}",
            f"ratelimit:lockout:{identifier}",
            f"ratelimit:burst:{identifier}",
        ]
        
        for pattern in patterns:
            keys = self.redis.keys(pattern)
            if keys:
                self.redis.delete(*keys)
        
        logger.info(f"Rate limit reset for {identifier}")
    
    def get_all_limited_identifiers(self) -> list:
        """Get all identifiers currently under rate limits."""
        lockout_keys = self.redis.keys("ratelimit:lockout:*")
        return [key.decode().split(":")[-1] for key in lockout_keys]


# Singleton instance
_rate_limiter = None


def get_rate_limiter() -> RateLimiter:
    """Get or create rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


def rate_limit_decorator(
    requests_per_minute: int = 60,
    requests_per_hour: int = 1000,
    limit_type: str = "user"
):
    """
    FastAPI decorator for rate limiting endpoints.
    
    Usage:
        @app.get("/scans")
        @rate_limit_decorator(requests_per_minute=30, requests_per_hour=500)
        async def get_scans(user: User = Depends(get_current_user)):
            ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract user from kwargs (FastAPI dependency injection)
            from fastapi import HTTPException, Request
            
            # Get request and user
            request = None
            user = None
            
            for key, value in kwargs.items():
                if hasattr(value, "__class__"):
                    if value.__class__.__name__ == "Request":
                        request = value
                    elif hasattr(value, "id"):  # Likely a User object
                        user = value
            
            # Determine identifier
            if user and hasattr(user, "id"):
                identifier = user.id
            elif request:
                identifier = request.client.host
            else:
                identifier = "unknown"
            
            # Check rate limit
            limiter = get_rate_limiter()
            allowed, metadata = limiter.check_rate_limit(
                identifier,
                limit_type=limit_type,
                requests_per_minute=requests_per_minute,
                requests_per_hour=requests_per_hour
            )
            
            if not allowed:
                raise HTTPException(
                    status_code=429,
                    detail={
                        "error": "rate_limit_exceeded",
                        "message": metadata.get("message", "Too many requests"),
                        "reset_at": metadata.get("minute_reset_at"),
                    }
                )
            
            # Call original function
            return await func(*args, **kwargs) if hasattr(func, "__await__") else func(*args, **kwargs)
        
        return wrapper
    return decorator


# Admin interface for managing rate limits
class RateLimitAdmin:
    """Admin interface for rate limit management."""
    
    def __init__(self, limiter: Optional[RateLimiter] = None):
        self.limiter = limiter or get_rate_limiter()
    
    def get_status(self, identifier: str) -> Dict:
        """Get status for identifier."""
        return self.limiter.get_status(identifier)
    
    def list_locked_out(self) -> list:
        """List all locked out identifiers."""
        return self.limiter.get_all_limited_identifiers()
    
    def unlock(self, identifier: str) -> None:
        """Unlock identifier."""
        self.limiter.reset_identifier(identifier)
    
    def update_config(self, requests_per_minute: Optional[int] = None,
                     requests_per_hour: Optional[int] = None) -> None:
        """Update rate limit config."""
        if requests_per_minute:
            self.limiter.config.requests_per_minute = requests_per_minute
        if requests_per_hour:
            self.limiter.config.requests_per_hour = requests_per_hour
