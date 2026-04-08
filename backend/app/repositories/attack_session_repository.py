from datetime import datetime

from app.extensions import db
from app.models.attack_session import AttackSession


class AttackSessionRepository:
    def create(self, **kwargs) -> AttackSession:
        item = AttackSession(**kwargs)
        db.session.add(item)
        db.session.commit()
        return item

    def save(self, session: AttackSession) -> AttackSession:
        db.session.add(session)
        db.session.commit()
        return session

    def get_by_id(self, session_id: str) -> AttackSession | None:
        return db.session.get(AttackSession, session_id)

    def find_recent_session(
        self,
        *,
        source_ip: str,
        honeypot_type: str,
        honeypot_id: str | None,
        min_end_time: datetime,
    ) -> AttackSession | None:
        query = AttackSession.query.filter(
            AttackSession.source_ip == source_ip,
            AttackSession.honeypot_type == honeypot_type,
        )

        if honeypot_id is None:
            query = query.filter(AttackSession.honeypot_id.is_(None))
        else:
            query = query.filter(AttackSession.honeypot_id == honeypot_id)

        return (
            query.filter(AttackSession.end_time >= min_end_time)
            .order_by(AttackSession.end_time.desc())
            .first()
        )

    def list_paginated(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        source_ip: str | None = None,
        honeypot_type: str | None = None,
        risk_level: str | None = None,
    ) -> dict:
        query = AttackSession.query

        if source_ip:
            query = query.filter(AttackSession.source_ip == source_ip)
        if honeypot_type:
            query = query.filter(AttackSession.honeypot_type == honeypot_type)
        if risk_level:
            query = query.filter(AttackSession.risk_level == risk_level)

        pagination = query.order_by(AttackSession.end_time.desc()).paginate(
            page=page,
            per_page=page_size,
            error_out=False,
        )

        return {
            "items": [item.to_dict() for item in pagination.items],
            "page": pagination.page,
            "page_size": pagination.per_page,
            "total": pagination.total,
            "pages": pagination.pages,
        }

    def list_by_source_ip(self, source_ip: str, limit: int = 100) -> list[AttackSession]:
        return (
            AttackSession.query.filter(AttackSession.source_ip == source_ip)
            .order_by(AttackSession.end_time.desc())
            .limit(limit)
            .all()
        )
