import csv
from datetime import datetime
from io import StringIO

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
        data = self._event_repository.list_paginated(
            page=page,
            page_size=page_size,
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
            sort_by=sort_by,
            sort_dir=sort_dir,
        )
        data["items"] = [self._to_list_item(item) for item in data["items"]]
        return data

    def get_attack(self, event_id: int) -> dict | None:
        event = self._event_repository.get_by_id(event_id)
        if event is None:
            return None
        return self._to_detail_item(event)

    def export_attacks(
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
    ) -> bytes:
        items = self._event_repository.list_filtered(
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
            sort_by=sort_by,
            sort_dir=sort_dir,
        )

        buffer = StringIO()
        writer = csv.DictWriter(
            buffer,
            fieldnames=[
                "id",
                "created_at",
                "source_ip",
                "honeypot_id",
                "country",
                "city",
                "session_id",
                "honeypot_type",
                "event_type",
                "risk_level",
                "risk_score",
                "request_method",
                "request_path",
                "request_preview",
                "matched_rules",
            ],
        )
        writer.writeheader()

        for item in items:
            row = self._to_list_item(item.to_dict())
            writer.writerow(
                {
                    "id": row.get("id"),
                    "created_at": row.get("created_at"),
                    "source_ip": row.get("source_ip"),
                    "honeypot_id": row.get("honeypot_id") or "",
                    "country": row.get("country") or "",
                    "city": row.get("city") or "",
                    "session_id": row.get("session_id") or "",
                    "honeypot_type": row.get("honeypot_type") or "",
                    "event_type": row.get("event_type") or "",
                    "risk_level": row.get("risk_level") or "",
                    "risk_score": row.get("risk_score") or 0,
                    "request_method": row.get("request_method") or "",
                    "request_path": row.get("request_path") or "",
                    "request_preview": row.get("request_preview") or "",
                    "matched_rules": " / ".join(
                        rule.get("title") or rule.get("key") or ""
                        for rule in (row.get("rule_details") or [])
                        if rule.get("title") or rule.get("key")
                    ),
                }
            )

        return buffer.getvalue().encode("utf-8-sig")

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
