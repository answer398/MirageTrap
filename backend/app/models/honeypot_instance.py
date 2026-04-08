from datetime import datetime, timedelta, timezone

from app.extensions import db


class HoneypotInstance(db.Model):
    __tablename__ = "honeypot_instances"

    id = db.Column(db.Integer, primary_key=True)
    honeypot_id = db.Column(db.String(64), nullable=False, unique=True, index=True)
    name = db.Column(db.String(128), nullable=False)
    honeypot_type = db.Column(db.String(16), nullable=False, default="web", index=True)
    image_key = db.Column(db.String(64), nullable=False)
    image_name = db.Column(db.String(255), nullable=False)
    container_name = db.Column(db.String(128), nullable=False, unique=True, index=True)
    host_ip = db.Column(db.String(64), nullable=True)
    bind_host = db.Column(db.String(64), nullable=False, default="0.0.0.0")
    exposed_port = db.Column(db.Integer, nullable=False, unique=True)
    container_port = db.Column(db.Integer, nullable=False, default=80)
    honeypot_profile = db.Column(db.String(32), nullable=False, default="portal")
    desired_state = db.Column(db.String(16), nullable=False, default="stopped")
    runtime_status = db.Column(db.String(16), nullable=False, default="stopped", index=True)
    container_id = db.Column(db.String(128), nullable=True)
    last_heartbeat_at = db.Column(db.DateTime(timezone=True), nullable=True)
    last_runtime_sync_at = db.Column(db.DateTime(timezone=True), nullable=True)
    last_seen_ip = db.Column(db.String(64), nullable=True)
    last_error = db.Column(db.Text, nullable=True)
    runtime_meta = db.Column(db.JSON, nullable=False, default=dict)
    created_at = db.Column(
        db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def heartbeat_state(self, timeout_seconds: int = 45) -> str:
        if self.runtime_status in {"stopped", "exited", "missing"}:
            return "offline"
        if self.last_heartbeat_at is None:
            return "unknown"

        now = datetime.now(timezone.utc)
        heartbeat_at = self.last_heartbeat_at
        if heartbeat_at.tzinfo is None:
            heartbeat_at = heartbeat_at.replace(tzinfo=timezone.utc)

        if heartbeat_at >= now - timedelta(seconds=max(timeout_seconds, 5)):
            return "online"
        return "stale"

    def to_dict(self, timeout_seconds: int = 45) -> dict:
        return {
            "id": self.id,
            "honeypot_id": self.honeypot_id,
            "name": self.name,
            "honeypot_type": self.honeypot_type,
            "image_key": self.image_key,
            "image_name": self.image_name,
            "container_name": self.container_name,
            "host_ip": self.host_ip,
            "bind_host": self.bind_host,
            "exposed_port": self.exposed_port,
            "container_port": self.container_port,
            "honeypot_profile": self.honeypot_profile,
            "desired_state": self.desired_state,
            "runtime_status": self.runtime_status,
            "heartbeat_state": self.heartbeat_state(timeout_seconds=timeout_seconds),
            "container_id": self.container_id,
            "last_heartbeat_at": self.last_heartbeat_at.isoformat() if self.last_heartbeat_at else None,
            "last_runtime_sync_at": self.last_runtime_sync_at.isoformat() if self.last_runtime_sync_at else None,
            "last_seen_ip": self.last_seen_ip,
            "last_error": self.last_error,
            "runtime_meta": dict(self.runtime_meta or {}),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
