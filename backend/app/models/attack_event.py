from datetime import datetime, timezone

from app.extensions import db


class AttackEvent(db.Model):
    __tablename__ = "attack_events"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(32), nullable=False, index=True)
    honeypot_type = db.Column(db.String(16), nullable=False, index=True)
    honeypot_id = db.Column(db.String(64), nullable=True, index=True)
    source_ip = db.Column(db.String(64), nullable=False, index=True)
    source_port = db.Column(db.Integer, nullable=True)
    country = db.Column(db.String(64), nullable=True)
    country_code = db.Column(db.String(8), nullable=True)
    region = db.Column(db.String(64), nullable=True)
    region_code = db.Column(db.String(32), nullable=True)
    city = db.Column(db.String(64), nullable=True)
    timezone = db.Column(db.String(64), nullable=True)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    accuracy_radius = db.Column(db.Integer, nullable=True)
    asn = db.Column(db.String(64), nullable=True)
    asn_org = db.Column(db.String(255), nullable=True)
    geo_source = db.Column(db.String(32), nullable=True)
    request_content = db.Column(db.Text, nullable=True)
    response_content = db.Column(db.Text, nullable=True)
    risk_level = db.Column(db.String(16), nullable=False, default="low", index=True)
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    threat_tags = db.Column(db.JSON, nullable=False, default=list)
    session_id = db.Column(
        db.String(64), db.ForeignKey("attack_sessions.session_id"), nullable=True, index=True
    )
    created_at = db.Column(
        db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "event_type": self.event_type,
            "honeypot_type": self.honeypot_type,
            "honeypot_id": self.honeypot_id,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "country": self.country,
            "country_code": self.country_code,
            "region": self.region,
            "region_code": self.region_code,
            "city": self.city,
            "timezone": self.timezone,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "accuracy_radius": self.accuracy_radius,
            "asn": self.asn,
            "asn_org": self.asn_org,
            "geo_source": self.geo_source,
            "request_content": self.request_content,
            "response_content": self.response_content,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "threat_tags": list(self.threat_tags or []),
            "session_id": self.session_id,
            "created_at": self.created_at.isoformat(),
        }
