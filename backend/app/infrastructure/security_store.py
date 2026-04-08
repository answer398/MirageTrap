from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Protocol


class SecurityStoreAdapter(Protocol):
    def revoke_token(self, *, jti: str, ttl_seconds: int) -> None:
        ...

    def is_token_revoked(self, *, jti: str) -> bool:
        ...

    def get_login_fail_count(self, *, key: str) -> int:
        ...

    def increment_login_fail(self, *, key: str, ttl_seconds: int) -> int:
        ...

    def reset_login_fail(self, *, key: str) -> None:
        ...

    def clear_runtime_state(self) -> None:
        ...

    def health_status(self) -> dict:
        ...


class InMemorySecurityStore:
    def __init__(self):
        self._revoked: dict[str, datetime] = {}
        self._login_fail: dict[str, tuple[int, datetime]] = {}

    def revoke_token(self, *, jti: str, ttl_seconds: int) -> None:
        if not jti:
            return
        expires_at = self._now() + timedelta(seconds=max(ttl_seconds, 60))
        self._revoked[jti] = expires_at

    def is_token_revoked(self, *, jti: str) -> bool:
        if not jti:
            return False
        self._cleanup_revoked()
        expires_at = self._revoked.get(jti)
        return bool(expires_at and expires_at > self._now())

    def get_login_fail_count(self, *, key: str) -> int:
        self._cleanup_login_fail()
        item = self._login_fail.get(key)
        return int(item[0]) if item else 0

    def increment_login_fail(self, *, key: str, ttl_seconds: int) -> int:
        self._cleanup_login_fail()
        now = self._now()
        item = self._login_fail.get(key)
        if item is None:
            count = 1
        else:
            count = item[0] + 1

        self._login_fail[key] = (count, now + timedelta(seconds=max(ttl_seconds, 60)))
        return count

    def reset_login_fail(self, *, key: str) -> None:
        self._login_fail.pop(key, None)

    def clear_runtime_state(self) -> None:
        self._revoked.clear()
        self._login_fail.clear()

    def health_status(self) -> dict:
        return {
            "status": "up",
            "driver": "memory",
            "message": "ok",
        }

    def _cleanup_revoked(self) -> None:
        now = self._now()
        for jti, expires_at in list(self._revoked.items()):
            if expires_at <= now:
                self._revoked.pop(jti, None)

    def _cleanup_login_fail(self) -> None:
        now = self._now()
        for key, (_, expires_at) in list(self._login_fail.items()):
            if expires_at <= now:
                self._login_fail.pop(key, None)

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)


def build_security_store(config) -> SecurityStoreAdapter:
    return InMemorySecurityStore()
