from app.extensions import db
from app.models.evidence_file import EvidenceFile


class EvidenceRepository:
    def create(self, **kwargs) -> EvidenceFile:
        item = EvidenceFile(**kwargs)
        db.session.add(item)
        db.session.commit()
        return item

    def get_by_id(self, file_id: int) -> EvidenceFile | None:
        return db.session.get(EvidenceFile, file_id)

    def list_by_session(self, session_id: str) -> list[EvidenceFile]:
        return (
            EvidenceFile.query.filter(EvidenceFile.session_id == session_id)
            .order_by(EvidenceFile.created_at.desc())
            .all()
        )
