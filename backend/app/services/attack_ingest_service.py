from datetime import datetime, timezone

from app.repositories.attack_event_repository import AttackEventRepository
from app.services.risk_engine_service import RiskEngineService
from app.services.session_service import SessionService
from app.utils.time import parse_iso_datetime
from app.utils.web_request import (
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
        geoip_lookup=None,
    ):
        self._event_repository = event_repository
        self._session_service = session_service
        self._risk_engine_service = risk_engine_service
        self._geoip_lookup = geoip_lookup

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
        event_time = parse_iso_datetime(payload.get("created_at")) or datetime.now(timezone.utc)

        risk = self._risk_engine_service.evaluate(
            event_type=event_type,
            honeypot_type=honeypot_type,
            request_record=request_record,
            response_record=response_record,
        )
        if honeypot_type == "web":
            event_type = str(risk.get("detected_event_type") or event_type or "web_req")

        session = self._session_service.resolve_session(
            source_ip=source_ip,
            honeypot_type=honeypot_type,
            honeypot_id=honeypot_id,
            event_time=event_time,
        )
        geo = self._resolve_geo_fields(source_ip=source_ip, payload=payload)

        event = self._event_repository.create(
            event_type=event_type,
            honeypot_type=honeypot_type,
            honeypot_id=honeypot_id,
            source_ip=source_ip,
            source_port=source_port,
            country=geo.get("country"),
            country_code=geo.get("country_code"),
            region=geo.get("region"),
            region_code=geo.get("region_code"),
            city=geo.get("city"),
            timezone=geo.get("timezone"),
            latitude=geo.get("latitude"),
            longitude=geo.get("longitude"),
            accuracy_radius=geo.get("accuracy_radius"),
            asn=geo.get("asn"),
            asn_org=geo.get("asn_org"),
            geo_source=geo.get("geo_source"),
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

    def _resolve_geo_fields(self, *, source_ip: str, payload: dict) -> dict:
        lookup = None
        if self._geoip_lookup is not None:
            try:
                lookup = self._geoip_lookup.lookup_ip(source_ip)
            except Exception:  # noqa: BLE001
                lookup = None

        payload_geo = {
            "country": self._coalesce_text(payload.get("country")),
            "country_code": self._coalesce_text(payload.get("country_code")),
            "region": self._coalesce_text(payload.get("region")),
            "region_code": self._coalesce_text(payload.get("region_code")),
            "city": self._coalesce_text(payload.get("city")),
            "timezone": self._coalesce_text(payload.get("timezone")),
            "latitude": self._coalesce_float(payload.get("latitude")),
            "longitude": self._coalesce_float(payload.get("longitude")),
            "accuracy_radius": self._coalesce_int(payload.get("accuracy_radius")),
            "asn": self._coalesce_text(payload.get("asn")),
            "asn_org": self._coalesce_text(payload.get("asn_org")),
        }

        if lookup:
            return {
                "country": self._coalesce_text(lookup.get("country")) or payload_geo["country"] or "unknown",
                "country_code": self._coalesce_text(lookup.get("country_code")) or payload_geo["country_code"],
                "region": self._coalesce_text(lookup.get("region")) or payload_geo["region"] or "",
                "region_code": self._coalesce_text(lookup.get("region_code")) or payload_geo["region_code"],
                "city": self._coalesce_text(lookup.get("city")) or payload_geo["city"] or "",
                "timezone": self._coalesce_text(lookup.get("timezone")) or payload_geo["timezone"],
                "latitude": self._coalesce_float(lookup.get("latitude"))
                if self._coalesce_float(lookup.get("latitude")) is not None
                else payload_geo["latitude"],
                "longitude": self._coalesce_float(lookup.get("longitude"))
                if self._coalesce_float(lookup.get("longitude")) is not None
                else payload_geo["longitude"],
                "accuracy_radius": self._coalesce_int(lookup.get("accuracy_radius"))
                if self._coalesce_int(lookup.get("accuracy_radius")) is not None
                else payload_geo["accuracy_radius"],
                "asn": self._coalesce_text(lookup.get("asn")) or payload_geo["asn"],
                "asn_org": self._coalesce_text(lookup.get("asn_org")) or payload_geo["asn_org"],
                "geo_source": self._coalesce_text(lookup.get("geo_source")) or "maxmind-geolite2",
                "tags": ["geoip"] if self._coalesce_text(lookup.get("geo_source")) == "maxmind-geolite2" else [],
            }

        return {
            "country": payload_geo["country"] or "unknown",
            "country_code": payload_geo["country_code"],
            "region": payload_geo["region"] or "",
            "region_code": payload_geo["region_code"],
            "city": payload_geo["city"] or "",
            "timezone": payload_geo["timezone"],
            "latitude": payload_geo["latitude"],
            "longitude": payload_geo["longitude"],
            "accuracy_radius": payload_geo["accuracy_radius"],
            "asn": payload_geo["asn"],
            "asn_org": payload_geo["asn_org"],
            "geo_source": "payload" if any(value for value in payload_geo.values() if value not in {"", None}) else "unknown",
            "tags": [],
        }

    @staticmethod
    def _coalesce_text(value) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @staticmethod
    def _coalesce_float(value) -> float | None:
        try:
            if value is None or value == "":
                return None
            result = float(value)
        except (TypeError, ValueError):
            return None
        if result != result:
            return None
        return result

    @staticmethod
    def _coalesce_int(value) -> int | None:
        try:
            if value is None or value == "":
                return None
            return int(value)
        except (TypeError, ValueError):
            return None
