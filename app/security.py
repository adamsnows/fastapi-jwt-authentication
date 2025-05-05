from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
import time
from typing import Dict, Tuple, List, Optional, Callable
import ipaddress
from pydantic import BaseModel


class RateLimiter:
    """Rate limiting implementation to prevent brute force attacks"""

    def __init__(
        self,
        times: int = 5,  # number of requests allowed
        seconds: int = 60,  # per time period (in seconds)
        ban_time: int = 300  # ban time in seconds after exceeding rate limit
    ):
        self.times = times
        self.seconds = seconds
        self.ban_time = ban_time

        # Store request times per IP
        self.requests: Dict[str, List[float]] = {}

        # Store banned IPs with expiration time
        self.banned_ips: Dict[str, float] = {}

    def _get_client_ip(self, request: Request) -> str:
        """Extract and normalize client IP from various headers"""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:

            client_ip = forwarded_for.split(",")[0].strip()
        else:
            client_ip = request.client.host if request.client else "0.0.0.0"

        try:
            ipaddress.ip_address(client_ip)
            return client_ip
        except ValueError:
            return "0.0.0.0"  # default for invalid IPs

    def _is_rate_limited(self, client_ip: str) -> Tuple[bool, Optional[int]]:
        """Check if client IP is rate limited and calculate retry-after time if needed"""
        current_time = time.time()

        if client_ip in self.banned_ips:
            ban_expiration = self.banned_ips[client_ip]
            if current_time < ban_expiration:
                time_remaining = int(ban_expiration - current_time)
                return True, time_remaining
            else:

                del self.banned_ips[client_ip]

        request_history = self.requests.get(client_ip, [])

        cutoff_time = current_time - self.seconds
        request_history = [t for t in request_history if t > cutoff_time]

        self.requests[client_ip] = request_history

        if len(request_history) >= self.times:
            self.banned_ips[client_ip] = current_time + self.ban_time
            return True, self.ban_time

        request_history.append(current_time)

        return False, None

    def _clean_old_data(self):
        """Clean up old IP data to prevent memory leaks"""
        current_time = time.time()

        self.banned_ips = {ip: expiry for ip, expiry in self.banned_ips.items()
                           if expiry > current_time}

        cutoff_time = current_time - self.seconds
        for ip in list(self.requests.keys()):
            self.requests[ip] = [t for t in self.requests[ip] if t > cutoff_time]
            if not self.requests[ip]:
                del self.requests[ip]

    async def __call__(self, request: Request, call_next: Callable):
        """Middleware function to check rate limits"""
        if time.time() % 60 < 1:
            self._clean_old_data()

        client_ip = self._get_client_ip(request)

        path = request.url.path.lower()
        method = request.method.lower()

        if (path.startswith("/auth/login") and method == "post") or \
           (path.startswith("/auth/password-reset") and method == "post"):

            is_limited, retry_after = self._is_rate_limited(client_ip)
            if is_limited:
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "detail": "Too many requests. Please try again later.",
                        "type": "rate_limit_exceeded"
                    },
                    headers={"Retry-After": str(retry_after)}
                )

        response = await call_next(request)
        return response


class LoginAttempt(BaseModel):
    username: str
    success: bool
    timestamp: float
    ip_address: str


class BruteForceProtection:
    """Protection against username enumeration and brute force attacks"""

    def __init__(self, max_attempts: int = 5, lockout_time: int = 1800):
        self.max_attempts = max_attempts
        self.lockout_time = lockout_time

        self.failed_attempts: Dict[str, List[LoginAttempt]] = {}

        self.locked_out: Dict[str, float] = {}

    def record_login_attempt(self, username: str, success: bool, ip_address: str):
        """Record a login attempt for a username"""
        current_time = time.time()

        attempt = LoginAttempt(
            username=username,
            success=success,
            timestamp=current_time,
            ip_address=ip_address
        )

        if username not in self.failed_attempts:
            self.failed_attempts[username] = []

        if success:
            self.failed_attempts[username] = []
            if username in self.locked_out:
                del self.locked_out[username]
            return

        self.failed_attempts[username].append(attempt)

        cutoff_time = current_time - self.lockout_time
        self.failed_attempts[username] = [
            a for a in self.failed_attempts[username]
            if a.timestamp > cutoff_time
        ]

        if len(self.failed_attempts[username]) >= self.max_attempts:
            self.locked_out[username] = current_time + self.lockout_time

    def is_locked_out(self, username: str) -> Tuple[bool, Optional[int]]:
        """Check if a username is locked out"""
        current_time = time.time()

        if username in self.locked_out:
            expiry_time = self.locked_out[username]
            if current_time < expiry_time:
                time_remaining = int(expiry_time - current_time)
                return True, time_remaining
            else:
                del self.locked_out[username]

                if username in self.failed_attempts:
                    self.failed_attempts[username] = []

        return False, None

    def clean_old_data(self):
        """Clean up old data to prevent memory leaks"""
        current_time = time.time()

        self.locked_out = {user: expiry for user, expiry in self.locked_out.items()
                           if expiry > current_time}

        cutoff_time = current_time - self.lockout_time
        for username in list(self.failed_attempts.keys()):
            self.failed_attempts[username] = [
                a for a in self.failed_attempts[username]
                if a.timestamp > cutoff_time
            ]
            if not self.failed_attempts[username]:
                del self.failed_attempts[username]


rate_limiter = RateLimiter()
brute_force_protection = BruteForceProtection()