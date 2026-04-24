from datetime import datetime, timezone

from sqlalchemy import asc, case, desc, func, or_

from app.extensions import db
from app.models.attack_event import AttackEvent


class AttackEventRepository:
    _NORMAL_EVENT_TYPE = "web_req"

    def create(self, **kwargs) -> AttackEvent:
        item = AttackEvent(**kwargs)
        db.session.add(item)
        db.session.commit()
        return item

    def get_by_id(self, event_id: int) -> AttackEvent | None:
        return db.session.get(AttackEvent, event_id)

    def list_by_ids(self, event_ids: list[int]) -> list[AttackEvent]:
        if not event_ids:
            return []
        return (
            AttackEvent.query.filter(AttackEvent.id.in_(event_ids))
            .order_by(AttackEvent.created_at.asc(), AttackEvent.id.asc())
            .all()
        )

    def delete_many(self, events: list[AttackEvent]) -> int:
        if not events:
            return 0
        for item in events:
            db.session.delete(item)
        db.session.commit()
        return len(events)

    def list_paginated(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        event_ids: list[int] | None = None,
        source_ip: str | None = None,
        honeypot_id: str | None = None,
        honeypot_type: str | None = None,
        risk_level: str | None = None,
        event_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        session_id: str | None = None,
        keyword: str | None = None,
        sort_by: str | None = None,
        sort_dir: str | None = None,
    ) -> dict:
        query = self._apply_list_filters(
            AttackEvent.query,
            event_ids=event_ids,
            source_ip=source_ip,
            honeypot_id=honeypot_id,
            honeypot_type=honeypot_type,
            risk_level=risk_level,
            event_type=event_type,
            start_time=start_time,
            end_time=end_time,
            session_id=session_id,
            keyword=keyword,
        )
        order_expressions = self._build_list_order_expressions(sort_by=sort_by, sort_dir=sort_dir)

        pagination = query.order_by(*order_expressions).paginate(
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

    def list_filtered(
        self,
        *,
        event_ids: list[int] | None = None,
        source_ip: str | None = None,
        honeypot_id: str | None = None,
        honeypot_type: str | None = None,
        risk_level: str | None = None,
        event_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        session_id: str | None = None,
        keyword: str | None = None,
        sort_by: str | None = None,
        sort_dir: str | None = None,
    ) -> list[AttackEvent]:
        query = self._apply_list_filters(
            AttackEvent.query,
            event_ids=event_ids,
            source_ip=source_ip,
            honeypot_id=honeypot_id,
            honeypot_type=honeypot_type,
            risk_level=risk_level,
            event_type=event_type,
            start_time=start_time,
            end_time=end_time,
            session_id=session_id,
            keyword=keyword,
        )
        return query.order_by(*self._build_list_order_expressions(sort_by=sort_by, sort_dir=sort_dir)).all()

    def count_total_since(self, start_time: datetime, *, attack_only: bool = False) -> int:
        query = AttackEvent.query.filter(AttackEvent.created_at >= start_time)
        query = self._apply_attack_only(query, attack_only=attack_only)
        return query.count()

    def count_unique_ip_since(self, start_time: datetime, *, attack_only: bool = False) -> int:
        query = db.session.query(func.count(func.distinct(AttackEvent.source_ip))).filter(
            AttackEvent.created_at >= start_time
        )
        query = self._apply_attack_only(query, attack_only=attack_only)
        return query.scalar() or 0

    def count_by_honeypot_since(
        self,
        start_time: datetime,
        honeypot_type: str,
        *,
        attack_only: bool = False,
    ) -> int:
        query = AttackEvent.query.filter(
            AttackEvent.created_at >= start_time,
            AttackEvent.honeypot_type == honeypot_type,
        )
        query = self._apply_attack_only(query, attack_only=attack_only)
        return query.count()

    def count_high_risk_since(self, start_time: datetime, *, attack_only: bool = False) -> int:
        query = AttackEvent.query.filter(
            AttackEvent.created_at >= start_time,
            AttackEvent.risk_level.in_(["high", "critical"]),
        )
        query = self._apply_attack_only(query, attack_only=attack_only)
        return query.count()

    def count_attack_types_since(self, start_time: datetime, *, attack_only: bool = False) -> int:
        query = db.session.query(func.count(func.distinct(AttackEvent.event_type))).filter(
            AttackEvent.created_at >= start_time
        )
        query = self._apply_attack_only(query, attack_only=attack_only)
        return query.scalar() or 0

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

    def list_since(
        self,
        start_time: datetime,
        limit: int = 1000,
        *,
        attack_only: bool = False,
    ) -> list[AttackEvent]:
        query = AttackEvent.query.filter(AttackEvent.created_at >= start_time)
        query = self._apply_attack_only(query, attack_only=attack_only)
        return query.order_by(AttackEvent.created_at.asc(), AttackEvent.id.asc()).limit(limit).all()

    def top_map_regions(
        self,
        *,
        start_time: datetime,
        limit: int = 20,
        attack_only: bool = False,
    ) -> list[dict]:
        high_risk_case = case(
            (AttackEvent.risk_level.in_(["high", "critical"]), 1),
            else_=0,
        )

        query = db.session.query(
            AttackEvent.country,
            AttackEvent.country_code,
            AttackEvent.region,
            AttackEvent.region_code,
            AttackEvent.city,
            AttackEvent.latitude,
            AttackEvent.longitude,
            func.count(AttackEvent.id).label("attack_count"),
            func.count(func.distinct(AttackEvent.source_ip)).label("unique_ip_count"),
            func.sum(high_risk_case).label("high_risk_count"),
            func.max(AttackEvent.created_at).label("latest_attack_at"),
        ).filter(AttackEvent.created_at >= start_time)
        query = self._apply_attack_only(query, attack_only=attack_only)
        rows = (
            query.group_by(
                AttackEvent.country,
                AttackEvent.country_code,
                AttackEvent.region,
                AttackEvent.region_code,
                AttackEvent.city,
                AttackEvent.latitude,
                AttackEvent.longitude,
            )
            .order_by(desc("attack_count"), desc("latest_attack_at"))
            .limit(limit)
            .all()
        )

        return [
            {
                "country": row.country or "unknown",
                "country_code": row.country_code or None,
                "region": row.region or "",
                "region_code": row.region_code or None,
                "city": row.city or "",
                "latitude": float(row.latitude) if row.latitude is not None else None,
                "longitude": float(row.longitude) if row.longitude is not None else None,
                "attack_count": int(row.attack_count or 0),
                "unique_ip_count": int(row.unique_ip_count or 0),
                "high_risk_count": int(row.high_risk_count or 0),
                "latest_attack_at": row.latest_attack_at.isoformat() if row.latest_attack_at else None,
            }
            for row in rows
        ]

    def top_attackers(
        self,
        *,
        start_time: datetime,
        limit: int = 20,
        attack_only: bool = False,
    ) -> list[dict]:
        high_risk_case = case(
            (AttackEvent.risk_level.in_(["high", "critical"]), 1),
            else_=0,
        )

        query = db.session.query(
            AttackEvent.source_ip,
            func.max(AttackEvent.country).label("country"),
            func.count(AttackEvent.id).label("attack_count"),
            func.count(func.distinct(AttackEvent.session_id)).label("session_count"),
            func.avg(AttackEvent.risk_score).label("avg_risk_score"),
            func.max(AttackEvent.risk_score).label("max_risk_score"),
            func.sum(high_risk_case).label("high_risk_count"),
            func.max(AttackEvent.created_at).label("latest_attack_at"),
        ).filter(AttackEvent.created_at >= start_time)
        query = self._apply_attack_only(query, attack_only=attack_only)
        rows = (
            query.group_by(AttackEvent.source_ip)
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

    def point_activity_details(
        self,
        *,
        start_time: datetime,
        country: str | None,
        region: str | None,
        city: str | None,
        latitude,
        longitude,
        attack_only: bool = False,
    ) -> dict:
        base_query = AttackEvent.query.filter(AttackEvent.created_at >= start_time)
        base_query = self._apply_attack_only(base_query, attack_only=attack_only)
        base_query = self._apply_point_scope(
            base_query,
            country=country,
            region=region,
            city=city,
            latitude=latitude,
            longitude=longitude,
        )

        ip_rows = (
            base_query.with_entities(
                AttackEvent.source_ip,
                func.count(AttackEvent.id).label("attack_count"),
                func.max(AttackEvent.created_at).label("latest_attack_at"),
            )
            .filter(AttackEvent.source_ip.isnot(None), AttackEvent.source_ip != "")
            .group_by(AttackEvent.source_ip)
            .order_by(desc("attack_count"), desc("latest_attack_at"), AttackEvent.source_ip.asc())
            .limit(3)
            .all()
        )

        type_rows = (
            base_query.with_entities(
                AttackEvent.event_type,
                func.count(AttackEvent.id).label("attack_count"),
                func.max(AttackEvent.created_at).label("latest_attack_at"),
            )
            .filter(AttackEvent.event_type.isnot(None), AttackEvent.event_type != "")
            .group_by(AttackEvent.event_type)
            .order_by(desc("attack_count"), desc("latest_attack_at"), AttackEvent.event_type.asc())
            .limit(3)
            .all()
        )

        latest_event = base_query.order_by(AttackEvent.created_at.desc(), AttackEvent.id.desc()).first()

        return {
            "primary_source_ip": ip_rows[0].source_ip if ip_rows else None,
            "sample_source_ips": [row.source_ip for row in ip_rows if row.source_ip],
            "attack_types": [
                {
                    "event_type": row.event_type,
                    "attack_count": int(row.attack_count or 0),
                }
                for row in type_rows
            ],
            "latest_event_type": latest_event.event_type if latest_event else None,
            "latest_risk_level": latest_event.risk_level if latest_event else None,
            "latest_attack_at": latest_event.created_at.isoformat() if latest_event else None,
            "latest_request_content": latest_event.request_content if latest_event else None,
        }

    def attack_type_distribution(
        self,
        *,
        start_time: datetime,
        limit: int = 20,
        attack_only: bool = False,
    ) -> list[dict]:
        query = db.session.query(
            AttackEvent.event_type,
            func.count(AttackEvent.id).label("attack_count"),
            func.max(AttackEvent.created_at).label("latest_attack_at"),
        ).filter(AttackEvent.created_at >= start_time)
        query = self._apply_attack_only(query, attack_only=attack_only)
        rows = (
            query.group_by(AttackEvent.event_type)
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

    def _apply_attack_only(self, query, *, attack_only: bool):
        if attack_only:
            query = query.filter(AttackEvent.event_type != self._NORMAL_EVENT_TYPE)
        return query

    def _apply_list_filters(
        self,
        query,
        *,
        event_ids: list[int] | None = None,
        source_ip: str | None = None,
        honeypot_id: str | None = None,
        honeypot_type: str | None = None,
        risk_level: str | None = None,
        event_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        session_id: str | None = None,
        keyword: str | None = None,
    ):
        if event_ids:
            query = query.filter(AttackEvent.id.in_(event_ids))
        if source_ip:
            query = query.filter(AttackEvent.source_ip == source_ip)
        if honeypot_id:
            query = query.filter(AttackEvent.honeypot_id == honeypot_id)
        if honeypot_type:
            query = query.filter(AttackEvent.honeypot_type == honeypot_type)
        if risk_level:
            query = query.filter(AttackEvent.risk_level == risk_level)
        if event_type:
            query = query.filter(AttackEvent.event_type == event_type)
        if session_id:
            query = query.filter(AttackEvent.session_id == session_id)
        if keyword:
            pattern = f"%{keyword.strip()}%"
            query = query.filter(
                or_(
                    AttackEvent.source_ip.ilike(pattern),
                    AttackEvent.session_id.ilike(pattern),
                    AttackEvent.country.ilike(pattern),
                    AttackEvent.city.ilike(pattern),
                    AttackEvent.asn_org.ilike(pattern),
                    AttackEvent.request_content.ilike(pattern),
                    AttackEvent.response_content.ilike(pattern),
                )
            )
        if start_time:
            query = query.filter(AttackEvent.created_at >= start_time)
        if end_time:
            query = query.filter(AttackEvent.created_at <= end_time)
        return query

    def _build_list_order_expressions(self, *, sort_by: str | None = None, sort_dir: str | None = None):
        normalized_sort_by = str(sort_by or "created_at").strip().lower()
        normalized_sort_dir = str(sort_dir or "desc").strip().lower()
        sort_column = {
            "created_at": AttackEvent.created_at,
            "risk_score": AttackEvent.risk_score,
            "source_ip": AttackEvent.source_ip,
            "event_type": AttackEvent.event_type,
        }.get(normalized_sort_by, AttackEvent.created_at)
        sort_expression = asc(sort_column) if normalized_sort_dir == "asc" else desc(sort_column)
        order_expressions = [sort_expression]
        if normalized_sort_by == "created_at":
            order_expressions.append(
                asc(AttackEvent.id) if normalized_sort_dir == "asc" else desc(AttackEvent.id)
            )
        else:
            order_expressions.extend([desc(AttackEvent.created_at), desc(AttackEvent.id)])
        return order_expressions

    def _apply_point_scope(
        self,
        query,
        *,
        country: str | None,
        region: str | None,
        city: str | None,
        latitude,
        longitude,
    ):
        normalized_country = str(country or "").strip()
        normalized_region = str(region or "").strip()
        normalized_city = str(city or "").strip()

        if normalized_country and normalized_country.lower() != "unknown":
            query = query.filter(AttackEvent.country == normalized_country)
        else:
            query = query.filter(
                or_(
                    AttackEvent.country.is_(None),
                    AttackEvent.country == "",
                    AttackEvent.country == "unknown",
                )
            )

        if normalized_region:
            query = query.filter(AttackEvent.region == normalized_region)
        else:
            query = query.filter(or_(AttackEvent.region.is_(None), AttackEvent.region == ""))

        if normalized_city:
            query = query.filter(AttackEvent.city == normalized_city)
        else:
            query = query.filter(or_(AttackEvent.city.is_(None), AttackEvent.city == ""))

        if latitude is None:
            query = query.filter(AttackEvent.latitude.is_(None))
        else:
            query = query.filter(AttackEvent.latitude == latitude)

        if longitude is None:
            query = query.filter(AttackEvent.longitude.is_(None))
        else:
            query = query.filter(AttackEvent.longitude == longitude)

        return query
