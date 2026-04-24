from app.repositories.attack_event_repository import AttackEventRepository
from app.repositories.attack_session_repository import AttackSessionRepository
from app.repositories.evidence_repository import EvidenceRepository
from app.utils import parse_request_content, request_preview


class AttackCommandService:
    _RISK_PRIORITY = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    def __init__(
        self,
        event_repository: AttackEventRepository,
        session_repository: AttackSessionRepository,
        evidence_repository: EvidenceRepository,
    ):
        self._event_repository = event_repository
        self._session_repository = session_repository
        self._evidence_repository = evidence_repository

    def delete_attack(self, event_id: int) -> tuple[dict | None, str | None]:
        return self.delete_attacks([event_id])

    def delete_attacks(self, event_ids: list[int]) -> tuple[dict | None, str | None]:
        normalized_ids = self._normalize_event_ids(event_ids)
        if not normalized_ids:
            return None, "至少选择一条攻击事件"

        events = self._event_repository.list_by_ids(normalized_ids)
        if not events:
            return None, "攻击事件不存在"

        deleted_ids = [item.id for item in events]
        deleted_id_set = set(deleted_ids)
        session_ids = sorted({item.session_id for item in events if item.session_id})

        self._event_repository.delete_many(events)

        session_updates = [self._sync_session(session_id) for session_id in session_ids]

        return (
            {
                "deleted_count": len(deleted_ids),
                "deleted_ids": deleted_ids,
                "missing_ids": [item for item in normalized_ids if item not in deleted_id_set],
                "session_updates": session_updates,
            },
            None,
        )

    def _sync_session(self, session_id: str) -> dict:
        session = self._session_repository.get_by_id(session_id)
        if session is None:
            return {"session_id": session_id, "status": "missing"}

        events = self._event_repository.list_by_session(session_id)
        if not events:
            evidence_files = self._evidence_repository.list_by_session(session_id)
            if evidence_files:
                session.event_count = 0
                session.risk_level = "low"
                session.summary = ""
                session.sample_count = 0
                self._session_repository.save(session)
                return {
                    "session_id": session_id,
                    "status": "emptied",
                    "event_count": 0,
                    "has_evidence": True,
                }

            self._session_repository.delete(session)
            return {
                "session_id": session_id,
                "status": "deleted",
                "event_count": 0,
                "has_evidence": False,
            }

        session.start_time = events[0].created_at
        session.end_time = events[-1].created_at
        session.event_count = len(events)
        session.risk_level = self._resolve_risk_level(events)
        session.summary = self._build_summary(events)
        self._session_repository.save(session)
        return {
            "session_id": session_id,
            "status": "updated",
            "event_count": session.event_count,
            "risk_level": session.risk_level,
        }

    def _resolve_risk_level(self, events: list) -> str:
        best_level = "low"
        best_priority = self._RISK_PRIORITY[best_level]
        for item in events:
            current_level = str(getattr(item, "risk_level", "") or "low").strip().lower()
            current_priority = self._RISK_PRIORITY.get(current_level, 0)
            if current_priority > best_priority:
                best_level = current_level
                best_priority = current_priority
        return best_level

    def _build_summary(self, events: list) -> str:
        lines = []
        seen = set()
        for item in events:
            record = parse_request_content(getattr(item, "request_content", None))
            clean_line = request_preview(record).strip()[:200]
            if not clean_line or clean_line in seen:
                continue
            seen.add(clean_line)
            lines.append(clean_line)

        if not lines:
            return ""
        return "\n".join(lines)[-1600:]

    @staticmethod
    def _normalize_event_ids(event_ids: list[int]) -> list[int]:
        if not isinstance(event_ids, list):
            return []

        normalized = []
        seen = set()
        for item in event_ids:
            try:
                event_id = int(item)
            except (TypeError, ValueError):
                continue
            if event_id <= 0 or event_id in seen:
                continue
            seen.add(event_id)
            normalized.append(event_id)
        return normalized
