from datetime import datetime, timedelta
from uuid import uuid4

from app.models.attack_session import AttackSession
from app.repositories.attack_session_repository import AttackSessionRepository


class SessionService:
    _RISK_PRIORITY = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    def __init__(self, session_repository: AttackSessionRepository, window_minutes: int = 30):
        self._session_repository = session_repository
        self._window_minutes = window_minutes

    def resolve_session(
        self,
        *,
        source_ip: str,
        honeypot_type: str,
        honeypot_id: str | None,
        event_time: datetime,
    ) -> AttackSession:
        window_start = event_time - timedelta(minutes=self._window_minutes)

        session = self._session_repository.find_recent_session(
            source_ip=source_ip,
            honeypot_type=honeypot_type,
            honeypot_id=honeypot_id,
            min_end_time=window_start,
        )

        if session is not None:
            return session

        return self._session_repository.create(
            session_id=f"sess_{uuid4().hex}",
            source_ip=source_ip,
            honeypot_type=honeypot_type,
            honeypot_id=honeypot_id,
            start_time=event_time,
            end_time=event_time,
            event_count=0,
            risk_level="low",
            replay_status="pending",
            sample_count=0,
            summary="",
        )

    def apply_event(
        self,
        *,
        session: AttackSession,
        event_time: datetime,
        risk_level: str,
        summary_line: str | None,
    ) -> AttackSession:
        session.event_count += 1
        session.end_time = event_time

        if self._RISK_PRIORITY[risk_level] > self._RISK_PRIORITY[session.risk_level]:
            session.risk_level = risk_level

        if summary_line:
            clean_line = summary_line.strip()[:200]
            if clean_line:
                if not session.summary:
                    session.summary = clean_line
                elif clean_line not in session.summary:
                    session.summary = f"{session.summary}\n{clean_line}"[-1600:]

        return self._session_repository.save(session)

    def list_sessions(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        source_ip: str | None = None,
        honeypot_type: str | None = None,
        risk_level: str | None = None,
    ) -> dict:
        return self._session_repository.list_paginated(
            page=page,
            page_size=page_size,
            source_ip=source_ip,
            honeypot_type=honeypot_type,
            risk_level=risk_level,
        )

    def get_session(self, session_id: str) -> AttackSession | None:
        return self._session_repository.get_by_id(session_id)
