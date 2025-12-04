"""
Rate Limiting for API endpoints
Prevents abuse and ensures fair usage.
"""

import os
import time
from typing import Optional, Callable
from collections import defaultdict
from datetime import datetime, timedelta
from fastapi import HTTPException, Request, status
from loguru import logger


class RateLimiter:
    """
    Token bucket rate limiter.

    Supports per-IP and per-API-key rate limiting.
    """

    def __init__(
        self,
        requests_per_minute: int = 60,
        burst_size: Optional[int] = None
    ):
        """
        Initialize rate limiter.

        Args:
            requests_per_minute: Maximum requests per minute
            burst_size: Maximum burst size (defaults to requests_per_minute)
        """
        self.requests_per_minute = requests_per_minute
        self.burst_size = burst_size or requests_per_minute

        # Token bucket: key -> (tokens, last_update_time)
        self.buckets = defaultdict(lambda: [self.burst_size, time.time()])

        # Statistics
        self.total_requests = 0
        self.total_rejected = 0

        logger.info(
            f"Rate limiter initialized: {requests_per_minute} req/min, "
            f"burst: {self.burst_size}"
        )

    def _refill_bucket(self, key: str) -> float:
        """
        Refill token bucket based on time elapsed.

        Returns:
            Current token count
        """
        tokens, last_update = self.buckets[key]
        now = time.time()
        elapsed = now - last_update

        # Refill tokens based on time elapsed
        tokens_to_add = (elapsed / 60.0) * self.requests_per_minute
        tokens = min(self.burst_size, tokens + tokens_to_add)

        # Update bucket
        self.buckets[key] = [tokens, now]

        return tokens

    def check_rate_limit(
        self,
        key: str,
        cost: float = 1.0
    ) -> tuple[bool, Optional[float]]:
        """
        Check if request is allowed under rate limit.

        Args:
            key: Identifier (IP address or API key)
            cost: Token cost (default: 1.0, expensive operations: 2.0+)

        Returns:
            (allowed, retry_after_seconds)
        """
        self.total_requests += 1

        # Refill bucket
        tokens = self._refill_bucket(key)

        # Check if enough tokens
        if tokens >= cost:
            # Consume tokens
            self.buckets[key][0] = tokens - cost
            return True, None
        else:
            # Rate limited
            self.total_rejected += 1

            # Calculate retry-after time
            tokens_needed = cost - tokens
            retry_after = (tokens_needed / self.requests_per_minute) * 60.0

            return False, retry_after

    def get_stats(self) -> dict:
        """Get rate limiter statistics."""
        return {
            "total_requests": self.total_requests,
            "total_rejected": self.total_rejected,
            "rejection_rate": (
                self.total_rejected / self.total_requests
                if self.total_requests > 0 else 0
            ),
            "active_keys": len(self.buckets)
        }

    def cleanup_old_buckets(self, max_age_hours: int = 24):
        """Remove old bucket entries to prevent memory leak."""
        now = time.time()
        max_age_seconds = max_age_hours * 3600

        keys_to_remove = [
            key for key, (_, last_update) in self.buckets.items()
            if now - last_update > max_age_seconds
        ]

        for key in keys_to_remove:
            del self.buckets[key]

        if keys_to_remove:
            logger.info(f"Cleaned up {len(keys_to_remove)} old rate limit buckets")


# Global rate limiter instances
_rate_limiters = {}


def get_rate_limiter(limiter_name: str = "default") -> RateLimiter:
    """Get or create rate limiter instance."""
    if limiter_name not in _rate_limiters:
        # Read configuration from environment
        rpm = int(os.getenv(f'RATE_LIMIT_{limiter_name.upper()}_RPM', '60'))
        burst = int(os.getenv(f'RATE_LIMIT_{limiter_name.upper()}_BURST', str(rpm)))

        _rate_limiters[limiter_name] = RateLimiter(
            requests_per_minute=rpm,
            burst_size=burst
        )

    return _rate_limiters[limiter_name]


async def rate_limit_dependency(
    request: Request,
    limiter_name: str = "default",
    cost: float = 1.0
):
    """
    FastAPI dependency for rate limiting.

    Usage:
        @app.get("/endpoint")
        async def endpoint(
            _: None = Depends(lambda r: rate_limit_dependency(r, "analysis", cost=2.0))
        ):
            ...
    """
    # Check if rate limiting is enabled
    rate_limit_enabled = os.getenv('RATE_LIMIT_ENABLED', 'true').lower() == 'true'

    if not rate_limit_enabled:
        return

    # Get limiter
    limiter = get_rate_limiter(limiter_name)

    # Determine key (prefer API key, fall back to IP)
    api_key = request.headers.get('X-API-Key')
    if api_key:
        key = f"key:{api_key[:10]}"  # Use first 10 chars to avoid storing full key
    else:
        # Use client IP
        client_ip = request.client.host if request.client else "unknown"
        key = f"ip:{client_ip}"

    # Check rate limit
    allowed, retry_after = limiter.check_rate_limit(key, cost)

    if not allowed:
        logger.warning(
            f"Rate limit exceeded for {key} on {limiter_name} "
            f"(retry after {retry_after:.1f}s)"
        )

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please slow down.",
            headers={"Retry-After": str(int(retry_after))}
        )


def create_rate_limit_dependency(limiter_name: str = "default", cost: float = 1.0):
    """
    Create a rate limit dependency with specific parameters.

    Usage:
        rate_limit_analysis = create_rate_limit_dependency("analysis", cost=2.0)

        @app.post("/analyze")
        async def analyze(request: Request, _: None = Depends(rate_limit_analysis)):
            ...
    """
    async def dependency(request: Request):
        return await rate_limit_dependency(request, limiter_name, cost)

    return dependency


# Pre-configured rate limit dependencies
rate_limit_default = create_rate_limit_dependency("default", cost=1.0)
rate_limit_analysis = create_rate_limit_dependency("analysis", cost=2.0)
rate_limit_batch = create_rate_limit_dependency("batch", cost=5.0)
rate_limit_admin = create_rate_limit_dependency("admin", cost=1.0)
