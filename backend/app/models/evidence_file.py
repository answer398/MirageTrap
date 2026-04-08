from datetime import datetime, timezone

from app.extensions import db


class EvidenceFile(db.Model):
    __tablename__ = "evidence_files"

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(
        db.String(64), db.ForeignKey("attack_sessions.session_id"), nullable=False, index=True
    )
    file_type = db.Column(db.String(32), nullable=False, index=True)
    object_key = db.Column(db.String(255), nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    size = db.Column(db.Integer, nullable=False, default=0)
    extra_data = db.Column(db.JSON, nullable=False, default=dict)
    created_at = db.Column(
        db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "file_type": self.file_type,
            "object_key": self.object_key,
            "sha256": self.sha256,
            "size": self.size,
            "extra_data": self.extra_data,
            "created_at": self.created_at.isoformat(),
        }
