from datetime import datetime, timezone

from flask_jwt_extended import create_access_token

from app.infrastructure import SecurityStoreAdapter
from app.models.admin_user import AdminUser
from app.repositories.admin_repository import AdminRepository


class AuthService:
    RATE_LIMITED_MESSAGE = "登录过于频繁，请稍后重试"

    def __init__(
        self,
        admin_repository: AdminRepository,
        security_store: SecurityStoreAdapter,
        max_attempts: int,
        lock_minutes: int,
        rate_limit_attempts: int,
        rate_limit_window_seconds: int,
        default_token_ttl_seconds: int,
    ):
        self._admin_repository = admin_repository
        self._security_store = security_store
        self._max_attempts = max_attempts
        self._lock_minutes = lock_minutes
        self._rate_limit_attempts = rate_limit_attempts
        self._rate_limit_window_seconds = rate_limit_window_seconds
        self._default_token_ttl_seconds = default_token_ttl_seconds

    def authenticate(self, username: str, password: str, source_ip: str | None = None) -> tuple[dict | None, str | None]:
        rate_key = self._rate_limit_key(username=username, source_ip=source_ip)
        if self._security_store.get_login_fail_count(key=rate_key) >= self._rate_limit_attempts:
            return None, self.RATE_LIMITED_MESSAGE

        user = self._admin_repository.get_by_username(username)
        if user is None:
            self._security_store.increment_login_fail(
                key=rate_key,
                ttl_seconds=self._rate_limit_window_seconds,
            )
            return None, "用户名或密码错误"

        if user.is_locked():
            return None, "账号已锁定，请稍后重试"

        if not user.check_password(password):
            self._security_store.increment_login_fail(
                key=rate_key,
                ttl_seconds=self._rate_limit_window_seconds,
            )
            user.register_failed_attempt(self._max_attempts, self._lock_minutes)
            self._admin_repository.save(user)
            return None, "用户名或密码错误"

        user.reset_failed_attempts()
        user.last_login_at = datetime.now(timezone.utc)
        self._admin_repository.save(user)
        self._security_store.reset_login_fail(key=rate_key)

        token = create_access_token(identity=str(user.id), additional_claims={"username": user.username})

        return {
            "access_token": token,
            "token_type": "Bearer",
            "profile": user.to_profile(),
        }, None

    def logout(
        self,
        jti: str,
        username: str,
        user_id: str,
        source_ip: str | None = None,
        token_exp: int | None = None,
    ) -> None:
        ttl_seconds = self._default_token_ttl_seconds
        if token_exp is not None:
            now_ts = int(datetime.now(timezone.utc).timestamp())
            ttl_seconds = max(token_exp - now_ts, 60)

        self._security_store.revoke_token(jti=jti, ttl_seconds=ttl_seconds)

    def get_profile(self, user_id: int) -> AdminUser | None:
        return self._admin_repository.get_by_id(user_id)

    @staticmethod
    def _rate_limit_key(*, username: str, source_ip: str | None) -> str:
        user_key = (username or "unknown").strip().lower()
        ip_key = (source_ip or "unknown").strip().lower()
        return f"{ip_key}:{user_key}"
