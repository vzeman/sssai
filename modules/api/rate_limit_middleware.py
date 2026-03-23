"""
FastAPI middleware for automatic rate limiting on all API requests.
"""

import logging
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from modules.api.rate_limiter import get_rate_limiter

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware that applies rate limiting to all API requests.
    
    Identifies requests by:
    1. User ID (if authenticated)
    2. IP address (if not authenticated)
    
    Usage:
        app.add_middleware(RateLimitMiddleware)
    """
    
    def __init__(self, app):
        super().__init__(app)
        self.limiter = get_rate_limiter()
        # Endpoints that should NOT be rate limited
        self.bypass_patterns = [
            "/health",
            "/docs",
            "/openapi.json",
            "/static",
            "/auth/register",
            "/auth/login",
            "/auth/refresh",
        ]
    
    async def dispatch(self, request: Request, call_next):
        """Apply rate limiting to request."""
        # Skip rate limiting for certain endpoints
        if self._should_bypass(request.url.path):
            return await call_next(request)
        
        # Get identifier (user ID if authenticated, IP otherwise)
        identifier = self._get_identifier(request)
        
        # Check rate limit
        allowed, metadata = self.limiter.check_rate_limit(
            identifier,
            limit_type="ip" if not request.scope.get("user") else "user"
        )
        
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "message": metadata.get("message", "Too many requests"),
                    "reset_at": metadata.get("minute_reset_at"),
                    "remaining": {
                        "minute": metadata.get("minute_remaining", 0),
                        "hour": metadata.get("hour_remaining", 0),
                    }
                },
                headers={
                    "X-RateLimit-Limit-Minute": str(metadata.get("minute_limit", 60)),
                    "X-RateLimit-Remaining-Minute": str(metadata.get("minute_remaining", 0)),
                    "X-RateLimit-Reset": str(int(metadata.get("minute_reset_at", 0))),
                    "X-RateLimit-Limit-Hour": str(metadata.get("hour_limit", 1000)),
                    "X-RateLimit-Remaining-Hour": str(metadata.get("hour_remaining", 0)),
                    "Retry-After": str(int(metadata.get("minute_reset_at", 0))),
                }
            )
        
        # Add rate limit headers to response
        response = await call_next(request)
        
        response.headers["X-RateLimit-Limit-Minute"] = str(metadata.get("minute_limit", 60))
        response.headers["X-RateLimit-Remaining-Minute"] = str(metadata.get("minute_remaining", 0))
        response.headers["X-RateLimit-Reset"] = str(int(metadata.get("minute_reset_at", 0)))
        response.headers["X-RateLimit-Limit-Hour"] = str(metadata.get("hour_limit", 1000))
        response.headers["X-RateLimit-Remaining-Hour"] = str(metadata.get("hour_remaining", 0))
        
        return response
    
    def _should_bypass(self, path: str) -> bool:
        """Check if path should bypass rate limiting."""
        for pattern in self.bypass_patterns:
            if path.startswith(pattern):
                return True
        return False
    
    def _get_identifier(self, request: Request) -> str:
        """
        Get unique identifier for request.
        
        Priority:
        1. User ID (if authenticated)
        2. IP address
        """
        # Try to get user from scope (if authenticated)
        if request.scope.get("user"):
            user = request.scope["user"]
            if hasattr(user, "id"):
                return user.id
        
        # Fall back to IP address
        client = request.client
        if client:
            return client.host
        
        # Fallback
        return "unknown"
