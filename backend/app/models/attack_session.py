from datetime import datetime, timezone

from app.extensions import db


class AttackSession(db.Model):
    __tablename__ = "attack_sessions"

    session_id = db.Column(db.String(64), primary_key=True)
    source_ip = db.Column(db.String(64), nullable=False, index=True)
    honeypot_type = db.Column(db.String(16), nullable=False, index=True)
    honeypot_id = db.Column(db.String(64), nullable=True, index=True)
    start_time = db.Column(db.DateTime(timezone=True), nullable=False)
    end_time = db.Column(db.DateTime(timezone=True), nullable=True)
    event_count = db.Column(db.Integer, nullable=False, default=0)
    risk_level = db.Column(db.String(16), nullable=False, default="low")
    replay_status = db.Column(db.String(32), nullable=False, default="pending")
    pcap_object_key = db.Column(db.String(255), nullable=True)
    sample_count = db.Column(db.Integer, nullable=False, default=0)
    summary = db.Column(db.Text, nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "honeypot_type": self.honeypot_type,
            "honeypot_id": self.honeypot_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "event_count": self.event_count,
            "risk_level": self.risk_level,
            "replay_status": self.replay_status,
            "pcap_object_key": self.pcap_object_key,
            "sample_count": self.sample_count,
            "summary": self.summary,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
