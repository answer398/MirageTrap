from app.repositories.attack_event_repository import AttackEventRepository
from app.repositories.attack_session_repository import AttackSessionRepository
from app.services.risk_engine_service import RiskEngineService
from app.utils.web_request import parse_request_content, request_preview


class ReplayService:
    def __init__(
        self,
        event_repository: AttackEventRepository,
        session_repository: AttackSessionRepository,
        risk_engine_service: RiskEngineService,
    ):
        self._event_repository = event_repository
        self._session_repository = session_repository
        self._risk_engine_service = risk_engine_service

    def get_session_timeline(self, session_id: str) -> dict | None:
        session = self._session_repository.get_by_id(session_id)
        if session is None:
            return None

        events = self._event_repository.list_by_session(session_id)

        return {
            "session": session.to_dict(),
            "timeline": [self._timeline_item(item) for item in events],
            "event_count": len(events),
        }

    def get_ip_replay(self, source_ip: str) -> dict:
        sessions = self._session_repository.list_by_source_ip(source_ip, limit=200)
        events = list(reversed(self._event_repository.list_by_source_ip(source_ip, limit=200)))

        return {
            "source_ip": source_ip,
            "total_sessions": len(sessions),
            "total_events": len(events),
            "sessions": [item.to_dict() for item in sessions],
            "timeline": [self._timeline_item(item) for item in events],
        }

    def _timeline_item(self, item) -> dict:
        request_info = parse_request_content(item.request_content)
        rule_keys = list(item.threat_tags or [])
        return {
            "event_id": item.id,
            "session_id": item.session_id,
            "time": item.created_at.isoformat(),
            "source_ip": item.source_ip,
            "event_type": item.event_type,
            "request_preview": request_preview(request_info),
            "request": request_info,
            "risk_level": item.risk_level,
            "risk_score": item.risk_score,
            "matched_rules": rule_keys,
            "rule_details": self._risk_engine_service.describe_rules(rule_keys),
        }
