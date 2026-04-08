from datetime import datetime, timezone

from app.repositories.attack_event_repository import AttackEventRepository
from app.services.risk_engine_service import RiskEngineService
from app.services.session_service import SessionService
from app.utils.time import parse_iso_datetime
from app.utils.web_request import (
    build_analysis_text,
    build_request_record,
    build_response_record,
    request_preview,
    serialize_request_record,
    serialize_response_record,
)


class AttackIngestService:
    _REQUIRED_FIELDS = ("event_type", "honeypot_type")
    _SUPPORTED_HONEYPOT_TYPES = {"web"}

    def __init__(
        self,
        event_repository: AttackEventRepository,
        session_service: SessionService,
        risk_engine_service: RiskEngineService,
    ):
        self._event_repository = event_repository
        self._session_service = session_service
        self._risk_engine_service = risk_engine_service

    def ingest_event(self, payload: dict, collector_ip: str | None = None) -> tuple[dict | None, str | None]:
        for field in self._REQUIRED_FIELDS:
            if not payload.get(field):
                return None, f"{field} 不能为空"

        event_type = str(payload["event_type"]).strip().lower()
        honeypot_type = str(payload["honeypot_type"]).strip().lower()
        if honeypot_type not in self._SUPPORTED_HONEYPOT_TYPES:
            return None, "honeypot_type 仅支持 web"

        source_ip = (payload.get("source_ip") or collector_ip or "unknown").strip()
        honeypot_id = payload.get("honeypot_id")
        source_port = payload.get("source_port")

        request_record = build_request_record(payload)
        response_record = build_response_record(payload)
        request_content = serialize_request_record(request_record)
        response_content = serialize_response_record(response_record)
        analysis_text = build_analysis_text(request_record)
        event_time = parse_iso_datetime(payload.get("created_at")) or datetime.now(timezone.utc)

        risk = self._risk_engine_service.evaluate(
            event_type=event_type,
            honeypot_type=honeypot_type,
            request_content=analysis_text,
            response_content=response_record.get("body"),
        )
        if honeypot_type == "web":
            event_type = str(risk.get("detected_event_type") or event_type or "web_req")

        session = self._session_service.resolve_session(
            source_ip=source_ip,
            honeypot_type=honeypot_type,
            honeypot_id=honeypot_id,
            event_time=event_time,
        )
        geo = {
            "country": payload.get("country") or "unknown",
            "region": payload.get("region") or "",
            "city": payload.get("city") or "",
            "asn": payload.get("asn"),
            "tags": [],
        }

        event = self._event_repository.create(
            event_type=event_type,
            honeypot_type=honeypot_type,
            honeypot_id=honeypot_id,
            source_ip=source_ip,
            source_port=source_port,
            country=geo.get("country"),
            region=geo.get("region"),
            city=geo.get("city"),
            asn=geo.get("asn"),
            request_content=request_content,
            response_content=response_content,
            risk_level=risk["risk_level"],
            risk_score=risk["risk_score"],
            threat_tags=list(risk["matched_rules"]),
            session_id=session.session_id,
            created_at=event_time,
        )

        updated_session = self._session_service.apply_event(
            session=session,
            event_time=event_time,
            risk_level=risk["risk_level"],
            summary_line=request_preview(request_record),
        )

        result = {
            "event": event.to_dict(),
            "session": updated_session.to_dict(),
            "geo": geo,
            "matched_rules": risk["matched_rules"],
            "matched_rule_details": self._risk_engine_service.describe_rules(risk["matched_rules"]),
        }

        return result, None
