import hashlib
import json
from datetime import datetime, timezone

from app.infrastructure import ObjectStorageAdapter
from app.repositories.attack_event_repository import AttackEventRepository
from app.repositories.attack_session_repository import AttackSessionRepository
from app.repositories.evidence_repository import EvidenceRepository
from app.utils.pcap import build_session_pcap
from app.utils.web_request import parse_request_content, request_preview


class EvidenceService:
    def __init__(
        self,
        evidence_repository: EvidenceRepository,
        session_repository: AttackSessionRepository,
        event_repository: AttackEventRepository,
        object_storage: ObjectStorageAdapter,
    ):
        self._evidence_repository = evidence_repository
        self._session_repository = session_repository
        self._event_repository = event_repository
        self._object_storage = object_storage

    def get_session_evidence(self, session_id: str) -> dict | None:
        session = self._session_repository.get_by_id(session_id)
        if session is None:
            return None

        files = self._evidence_repository.list_by_session(session_id)
        events = self._event_repository.list_by_session(session_id)
        high_risk_count = len([item for item in events if item.risk_level in {"high", "critical"}])

        return {
            "session": session.to_dict(),
            "stats": {
                "event_count": len(events),
                "file_count": len(files),
                "high_risk_event_count": high_risk_count,
            },
            "files": [item.to_dict() for item in files],
            "timeline": [
                {
                    "event_id": item.id,
                    "time": item.created_at.isoformat(),
                    "event_type": item.event_type,
                    "request_preview": request_preview(parse_request_content(item.request_content)),
                    "risk_level": item.risk_level,
                    "risk_score": item.risk_score,
                }
                for item in events
            ],
        }

    def export_session_evidence(
        self,
        session_id: str,
        *,
        export_format: str = "json",
    ) -> tuple[dict | None, str | None]:
        session = self._session_repository.get_by_id(session_id)
        if session is None:
            return None, "攻击会话不存在"

        export_format = str(export_format or "json").strip().lower()
        if export_format not in {"json", "pcap"}:
            return None, "仅支持 json/pcap 导出格式"

        now = datetime.now(timezone.utc)
        events = self._event_repository.list_by_session(session_id)
        payload_bytes, ext, content_type = self._build_export_blob(
            session=session.to_dict(),
            events=events,
            export_format=export_format,
        )
        checksum = hashlib.sha256(payload_bytes).hexdigest()
        size = len(payload_bytes)

        object_key = f"exports/{session_id}/session_{session_id}_{now.strftime('%Y%m%d%H%M%S')}.{ext}"
        storage_error = self._object_storage.put_object(
            object_key=object_key,
            data=payload_bytes,
            content_type=content_type,
        )
        if storage_error:
            return None, f"证据包写入存储失败: {storage_error}"

        file_item = self._evidence_repository.create(
            session_id=session_id,
            file_type=f"{export_format}_export",
            object_key=object_key,
            sha256=checksum,
            size=size,
            extra_data={
                "format": export_format,
                "generated_at": now.isoformat(),
                "content_type": content_type,
                "download_name": f"{session_id}.{ext}",
            },
        )

        return {
            "file": file_item.to_dict(),
            "download_url": f"/api/files/{file_item.id}/download",
            "preview": {
                "session_id": session_id,
                "event_count": len(events),
                "high_risk_event_count": len(
                    [item for item in events if item.risk_level in {"high", "critical"}]
                ),
            },
        }, None

    def get_file(self, file_id: int):
        return self._evidence_repository.get_by_id(file_id)

    def get_file_download(self, file_id: int) -> tuple[dict | None, str | None]:
        file_item = self._evidence_repository.get_by_id(file_id)
        if file_item is None:
            return None, "证据文件不存在"

        raw, read_error = self._object_storage.get_object(object_key=file_item.object_key)
        if read_error or raw is None:
            return None, f"证据对象读取失败: {read_error or 'unknown error'}"

        return {
            "file": file_item,
            "bytes": raw,
            "download_name": str(file_item.extra_data.get("download_name") or f"file-{file_id}.bin"),
            "content_type": str(
                file_item.extra_data.get("content_type") or "application/octet-stream"
            ),
        }, None

    def verify_file_integrity(self, file_id: int) -> tuple[dict | None, str | None]:
        file_item = self._evidence_repository.get_by_id(file_id)
        if file_item is None:
            return None, "证据文件不存在"

        raw, read_error = self._object_storage.get_object(object_key=file_item.object_key)
        if read_error or raw is None:
            return None, f"证据对象读取失败: {read_error or 'unknown error'}"

        actual_size = len(raw)
        actual_sha256 = hashlib.sha256(raw).hexdigest()
        verified = actual_size == int(file_item.size) and actual_sha256 == file_item.sha256

        return {
            "file_id": file_item.id,
            "object_key": file_item.object_key,
            "expected_sha256": file_item.sha256,
            "actual_sha256": actual_sha256,
            "expected_size": int(file_item.size),
            "actual_size": actual_size,
            "verified": verified,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }, None

    @staticmethod
    def _build_export_blob(*, session: dict, events: list, export_format: str) -> tuple[bytes, str, str]:
        if export_format == "pcap":
            return build_session_pcap(events), "pcap", "application/vnd.tcpdump.pcap"

        timeline = []
        for item in events:
            request_info = parse_request_content(item.request_content)
            timeline.append(
                {
                    "event_id": item.id,
                    "time": item.created_at.isoformat(),
                    "event_type": item.event_type,
                    "source_ip": item.source_ip,
                    "request_preview": request_preview(request_info),
                    "request": request_info,
                    "risk_level": item.risk_level,
                    "risk_score": item.risk_score,
                    "matched_rules": list(item.threat_tags or []),
                }
            )

        serialized = json.dumps(
            {
                "session": session,
                "timeline": timeline,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        return serialized.encode("utf-8"), "json", "application/json"
