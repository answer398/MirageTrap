from datetime import datetime

from app.models.attack_event import AttackEvent
from app.repositories.attack_event_repository import AttackEventRepository
from app.services.risk_engine_service import RiskEngineService
from app.utils.web_request import parse_request_content, parse_response_content, request_preview


class AttackQueryService:
    def __init__(
        self,
        event_repository: AttackEventRepository,
        risk_engine_service: RiskEngineService,
    ):
        self._event_repository = event_repository
        self._risk_engine_service = risk_engine_service

    def list_attacks(
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
        data = self._event_repository.list_paginated(
            page=page,
            page_size=page_size,
            source_ip=source_ip,
            honeypot_type=honeypot_type,
            risk_level=risk_level,
            start_time=start_time,
            end_time=end_time,
            session_id=session_id,
        )
        data["items"] = [self._to_list_item(item) for item in data["items"]]
        return data

    def get_attack(self, event_id: int) -> dict | None:
        event = self._event_repository.get_by_id(event_id)
        if event is None:
            return None
        return self._to_detail_item(event)

    def _to_list_item(self, item: dict) -> dict:
        request_info = parse_request_content(item.get("request_content"))
        rule_keys = list(item.get("threat_tags") or [])
        return {
            **item,
            "request_method": request_info.get("method") or "GET",
            "request_path": request_info.get("path") or "/",
            "request_preview": request_preview(request_info),
            "matched_rules": rule_keys,
            "rule_details": self._risk_engine_service.describe_rules(rule_keys),
        }

    def _to_detail_item(self, event: AttackEvent) -> dict:
        data = event.to_dict()
        request_info = parse_request_content(data.get("request_content"))
        response_info = parse_response_content(data.get("response_content"))
        rule_keys = list(data.get("threat_tags") or [])
        return {
            **data,
            "request_method": request_info.get("method") or "GET",
            "request_path": request_info.get("path") or "/",
            "request_preview": request_preview(request_info),
            "matched_rules": rule_keys,
            "rule_details": self._risk_engine_service.describe_rules(rule_keys),
            "request": request_info,
            "response": response_info,
        }
