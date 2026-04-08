from datetime import datetime, timezone

from sqlalchemy import case, desc, func

from app.extensions import db
from app.models.attack_event import AttackEvent


class AttackEventRepository:
    def create(self, **kwargs) -> AttackEvent:
        item = AttackEvent(**kwargs)
        db.session.add(item)
        db.session.commit()
        return item

    def get_by_id(self, event_id: int) -> AttackEvent | None:
        return db.session.get(AttackEvent, event_id)

    def list_paginated(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        source_ip: str | None = None,
        honeypot_type: str | None = None,
        risk_level: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        session_id: str | None = None,
    ) -> dict:
        query = AttackEvent.query

        if source_ip:
            query = query.filter(AttackEvent.source_ip == source_ip)
        if honeypot_type:
            query = query.filter(AttackEvent.honeypot_type == honeypot_type)
        if risk_level:
            query = query.filter(AttackEvent.risk_level == risk_level)
        if session_id:
            query = query.filter(AttackEvent.session_id == session_id)
        if start_time:
            query = query.filter(AttackEvent.created_at >= start_time)
        if end_time:
            query = query.filter(AttackEvent.created_at <= end_time)

        pagination = query.order_by(AttackEvent.created_at.desc()).paginate(
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

    def count_total_since(self, start_time: datetime) -> int:
        return AttackEvent.query.filter(AttackEvent.created_at >= start_time).count()

    def count_unique_ip_since(self, start_time: datetime) -> int:
        return (
            db.session.query(func.count(func.distinct(AttackEvent.source_ip)))
            .filter(AttackEvent.created_at >= start_time)
            .scalar()
            or 0
        )

    def count_by_honeypot_since(self, start_time: datetime, honeypot_type: str) -> int:
        return (
            AttackEvent.query.filter(
                AttackEvent.created_at >= start_time,
                AttackEvent.honeypot_type == honeypot_type,
            ).count()
        )

    def count_high_risk_since(self, start_time: datetime) -> int:
        return (
            AttackEvent.query.filter(
                AttackEvent.created_at >= start_time,
                AttackEvent.risk_level.in_(["high", "critical"]),
            ).count()
        )

    def count_attack_types_since(self, start_time: datetime) -> int:
        return (
            db.session.query(func.count(func.distinct(AttackEvent.event_type)))
            .filter(AttackEvent.created_at >= start_time)
            .scalar()
            or 0
        )

    def list_by_session(self, session_id: str) -> list[AttackEvent]:
        return (
            AttackEvent.query.filter(AttackEvent.session_id == session_id)
            .order_by(AttackEvent.created_at.asc(), AttackEvent.id.asc())
            .all()
        )

    def list_by_source_ip(self, source_ip: str, limit: int = 200) -> list[AttackEvent]:
        return (
            AttackEvent.query.filter(AttackEvent.source_ip == source_ip)
            .order_by(AttackEvent.created_at.desc(), AttackEvent.id.desc())
            .limit(limit)
            .all()
        )

    def list_since(self, start_time: datetime, limit: int = 1000) -> list[AttackEvent]:
        return (
            AttackEvent.query.filter(AttackEvent.created_at >= start_time)
            .order_by(AttackEvent.created_at.asc(), AttackEvent.id.asc())
            .limit(limit)
            .all()
        )

    def top_map_regions(self, *, start_time: datetime, limit: int = 20) -> list[dict]:
        high_risk_case = case(
            (AttackEvent.risk_level.in_(["high", "critical"]), 1),
            else_=0,
        )

        rows = (
            db.session.query(
                AttackEvent.country,
                AttackEvent.region,
                AttackEvent.city,
                func.count(AttackEvent.id).label("attack_count"),
                func.count(func.distinct(AttackEvent.source_ip)).label("unique_ip_count"),
                func.sum(high_risk_case).label("high_risk_count"),
                func.max(AttackEvent.created_at).label("latest_attack_at"),
            )
            .filter(AttackEvent.created_at >= start_time)
            .group_by(AttackEvent.country, AttackEvent.region, AttackEvent.city)
            .order_by(desc("attack_count"), desc("latest_attack_at"))
            .limit(limit)
            .all()
        )

        return [
            {
                "country": row.country or "unknown",
                "region": row.region or "",
                "city": row.city or "",
                "attack_count": int(row.attack_count or 0),
                "unique_ip_count": int(row.unique_ip_count or 0),
                "high_risk_count": int(row.high_risk_count or 0),
                "latest_attack_at": row.latest_attack_at.isoformat() if row.latest_attack_at else None,
            }
            for row in rows
        ]

    def top_attackers(self, *, start_time: datetime, limit: int = 20) -> list[dict]:
        high_risk_case = case(
            (AttackEvent.risk_level.in_(["high", "critical"]), 1),
            else_=0,
        )

        rows = (
            db.session.query(
                AttackEvent.source_ip,
                func.max(AttackEvent.country).label("country"),
                func.count(AttackEvent.id).label("attack_count"),
                func.count(func.distinct(AttackEvent.session_id)).label("session_count"),
                func.avg(AttackEvent.risk_score).label("avg_risk_score"),
                func.max(AttackEvent.risk_score).label("max_risk_score"),
                func.sum(high_risk_case).label("high_risk_count"),
                func.max(AttackEvent.created_at).label("latest_attack_at"),
            )
            .filter(AttackEvent.created_at >= start_time)
            .group_by(AttackEvent.source_ip)
            .order_by(desc("attack_count"), desc("latest_attack_at"))
            .limit(limit)
            .all()
        )

        return [
            {
                "source_ip": row.source_ip,
                "country": row.country or "unknown",
                "attack_count": int(row.attack_count or 0),
                "session_count": int(row.session_count or 0),
                "avg_risk_score": round(float(row.avg_risk_score or 0), 2),
                "max_risk_score": int(row.max_risk_score or 0),
                "high_risk_count": int(row.high_risk_count or 0),
                "latest_attack_at": row.latest_attack_at.isoformat() if row.latest_attack_at else None,
            }
            for row in rows
        ]

    def attack_type_distribution(self, *, start_time: datetime, limit: int = 20) -> list[dict]:
        rows = (
            db.session.query(
                AttackEvent.event_type,
                func.count(AttackEvent.id).label("attack_count"),
                func.max(AttackEvent.created_at).label("latest_attack_at"),
            )
            .filter(AttackEvent.created_at >= start_time)
            .group_by(AttackEvent.event_type)
            .order_by(desc("attack_count"), desc("latest_attack_at"))
            .limit(limit)
            .all()
        )

        return [
            {
                "event_type": row.event_type,
                "attack_count": int(row.attack_count or 0),
                "latest_attack_at": row.latest_attack_at.isoformat() if row.latest_attack_at else None,
            }
            for row in rows
        ]
