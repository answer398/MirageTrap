from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import text

from app.extensions import db


class HealthService:
    def __init__(
        self,
        *,
        app_name: str,
        security_store,
        object_storage,
        geoip_lookup,
        honeypot_runtime,
    ):
        self._app_name = app_name
        self._security_store = security_store
        self._object_storage = object_storage
        self._geoip_lookup = geoip_lookup
        self._honeypot_runtime = honeypot_runtime

    def liveness(self) -> dict:
        return {
            "service": self._app_name,
            "status": "up",
            "time": datetime.now(timezone.utc).isoformat(),
        }

    def readiness(self) -> dict:
        checks = {
            "database": self._check_database(),
            "security_store": self._check_security_store(),
            "object_storage": self._check_object_storage(),
            "geoip_lookup": self._check_geoip_lookup(),
            "honeypot_runtime": self._check_honeypot_runtime(),
        }

        down_components = [name for name, result in checks.items() if result["status"] != "up"]
        overall_status = "up" if not down_components else "degraded"

        return {
            "service": self._app_name,
            "status": overall_status,
            "time": datetime.now(timezone.utc).isoformat(),
            "components": checks,
            "summary": {
                "total": len(checks),
                "up": len(checks) - len(down_components),
                "degraded": len(down_components),
                "degraded_components": down_components,
            },
        }

    @staticmethod
    def _check_database() -> dict:
        try:
            db.session.execute(text("SELECT 1"))
            return {"status": "up", "message": "ok"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "down", "message": str(exc)}

    def _check_security_store(self) -> dict:
        try:
            health_fn = getattr(self._security_store, "health_status", None)
            if callable(health_fn):
                return health_fn()
            return {"status": "up", "message": "no health_status() implemented"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "down", "message": str(exc)}

    def _check_object_storage(self) -> dict:
        try:
            health_fn = getattr(self._object_storage, "health_status", None)
            if callable(health_fn):
                return health_fn()
            return {"status": "up", "message": "no health_status() implemented"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "down", "message": str(exc)}

    def _check_geoip_lookup(self) -> dict:
        try:
            health_fn = getattr(self._geoip_lookup, "health_status", None)
            if callable(health_fn):
                return health_fn()
            return {"status": "up", "message": "no health_status() implemented"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "down", "message": str(exc)}

    def _check_honeypot_runtime(self) -> dict:
        try:
            health_fn = getattr(self._honeypot_runtime, "health_status", None)
            if callable(health_fn):
                return health_fn()
            return {"status": "up", "message": "no health_status() implemented"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "down", "message": str(exc)}
