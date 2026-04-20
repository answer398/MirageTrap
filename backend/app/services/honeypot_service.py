from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from uuid import uuid4

from app.models.honeypot_instance import HoneypotInstance
from app.repositories.honeypot_repository import HoneypotRepository
from app.utils.time import parse_iso_datetime


class HoneypotService:
    _SUPPORTED_TYPES = {"web"}
    _CATALOG = [
        {
            "key": "web_portal",
            "label": "企业门户镜像",
            "description": "默认企业登录入口诱捕页",
            "honeypot_type": "web",
            "image_name": "miragetrap/web-honeypot:latest",
            "profile": "portal",
            "container_port": 80,
            "default_exposed_port": 18080,
        },
        {
            "key": "web_search",
            "label": "知识检索镜像",
            "description": "突出搜索和检索场景的 Web 诱捕页",
            "honeypot_type": "web",
            "image_name": "miragetrap/web-honeypot:latest",
            "profile": "search",
            "container_port": 80,
            "default_exposed_port": 18081,
        },
        {
            "key": "web_admin",
            "label": "运维后台镜像",
            "description": "突出后台入口与管理界面的 Web 诱捕页",
            "honeypot_type": "web",
            "image_name": "miragetrap/web-honeypot:latest",
            "profile": "admin",
            "container_port": 80,
            "default_exposed_port": 18082,
        },
    ]

    def __init__(
        self,
        *,
        honeypot_repository: HoneypotRepository,
        runtime_adapter,
        controller_base_url: str,
        controller_public_base_url: str,
        control_token: str,
        ingest_token: str,
        heartbeat_timeout_seconds: int = 45,
        startup_verify_seconds: int = 6,
    ):
        self._honeypot_repository = honeypot_repository
        self._runtime_adapter = runtime_adapter
        self._controller_base_url = controller_base_url
        self._controller_public_base_url = controller_public_base_url
        self._control_token = control_token
        self._ingest_token = ingest_token
        self._heartbeat_timeout_seconds = heartbeat_timeout_seconds
        self._startup_verify_seconds = max(int(startup_verify_seconds), 0)

    def catalog(self) -> dict:
        return {"items": [dict(item) for item in self._CATALOG]}

    def list_instances(self, *, page: int = 1, page_size: int = 20, refresh_runtime: bool = True) -> dict:
        data = self._honeypot_repository.list_paginated(page=page, page_size=page_size)
        items = list(data["items"])
        if refresh_runtime:
            for item in items:
                self._sync_runtime_state(item)

        summary = self._summarize(items)
        return {
            "items": [self._serialize(item) for item in items],
            "page": data["page"],
            "page_size": data["page_size"],
            "total": data["total"],
            "pages": data["pages"],
            "summary": summary,
        }

    def get_instance(self, instance_id: int, *, refresh_runtime: bool = True) -> HoneypotInstance | None:
        item = self._honeypot_repository.get_by_id(instance_id)
        if item is not None and refresh_runtime:
            self._sync_runtime_state(item)
        return item

    def create_instance(self, payload: dict) -> tuple[dict | None, str | None]:
        name = str(payload.get("name") or "").strip()
        image_key = str(payload.get("image_key") or "").strip()
        honeypot_type = str(payload.get("honeypot_type") or "web").strip().lower()
        exposed_port = payload.get("exposed_port")

        if not name:
            return None, "name 不能为空"
        if honeypot_type not in self._SUPPORTED_TYPES:
            return None, "当前仅支持 web 蜜罐"

        image_spec = self._find_catalog_item(image_key)
        if image_spec is None:
            return None, "image_key 不在允许的枚举列表中"

        port, error = self._normalize_port(exposed_port or image_spec["default_exposed_port"])
        if error:
            return None, error

        port_holder = self._honeypot_repository.get_by_exposed_port(port)
        if port_holder is not None:
            return None, f"端口 {port} 已被蜜罐 {port_holder.name} 占用"

        container_name = self._generate_container_name(name=name)
        honeypot_id = self._generate_honeypot_id()

        item = self._honeypot_repository.create(
            honeypot_id=honeypot_id,
            name=name,
            honeypot_type=honeypot_type,
            image_key=image_spec["key"],
            image_name=image_spec["image_name"],
            container_name=container_name,
            bind_host="0.0.0.0",
            exposed_port=port,
            container_port=image_spec["container_port"],
            honeypot_profile=image_spec["profile"],
            desired_state="stopped",
            runtime_status="stopped",
            runtime_meta={"catalog_label": image_spec["label"]},
        )
        return self._serialize(item), None

    def start_instance(self, instance_id: int) -> tuple[dict | None, str | None, int | None]:
        item = self._honeypot_repository.get_by_id(instance_id)
        if item is None:
            return None, "蜜罐实例不存在", 404

        image_spec = self._find_catalog_item(item.image_key)
        if image_spec is None:
            return None, "蜜罐镜像目录配置丢失", 422

        try:
            runtime = self._runtime_adapter.start_instance(
                item,
                image_spec,
                self._control_plane_payload(),
            )
        except Exception as exc:  # noqa: BLE001
            item.last_error = str(exc)
            self._honeypot_repository.save(item)
            return None, str(exc), 502

        item.desired_state = "running"
        self._apply_runtime_payload(item, runtime)
        item.last_error = None
        self._honeypot_repository.save(item)

        startup_error = self._verify_started_instance(item)
        if startup_error:
            return None, startup_error, 502
        return self._serialize(item), None, None

    def stop_instance(self, instance_id: int) -> tuple[dict | None, str | None, int | None]:
        item = self._honeypot_repository.get_by_id(instance_id)
        if item is None:
            return None, "蜜罐实例不存在", 404

        try:
            runtime = self._runtime_adapter.stop_instance(item)
        except Exception as exc:  # noqa: BLE001
            item.last_error = str(exc)
            self._honeypot_repository.save(item)
            return None, str(exc), 502

        item.desired_state = "stopped"
        self._apply_runtime_payload(item, runtime)
        self._honeypot_repository.save(item)
        return self._serialize(item), None, None

    def delete_instance(self, instance_id: int) -> tuple[dict | None, str | None, int | None]:
        item = self._honeypot_repository.get_by_id(instance_id)
        if item is None:
            return None, "蜜罐实例不存在", 404

        try:
            self._runtime_adapter.delete_instance(item)
        except Exception as exc:  # noqa: BLE001
            return None, str(exc), 502

        self._honeypot_repository.delete(item)
        return {"deleted": True}, None, None

    def record_heartbeat(self, payload: dict, *, collector_ip: str | None = None) -> tuple[dict | None, str | None]:
        honeypot_id = str(payload.get("honeypot_id") or "").strip()
        if not honeypot_id:
            return None, "honeypot_id 不能为空"

        honeypot_type = str(payload.get("honeypot_type") or "web").strip().lower()
        if honeypot_type not in self._SUPPORTED_TYPES:
            return None, "当前仅支持 web 蜜罐"

        image_key = str(payload.get("image_key") or "web_portal").strip()
        image_spec = self._find_catalog_item(image_key) or self._CATALOG[0]

        item = self._honeypot_repository.get_by_honeypot_id(honeypot_id)
        if item is None:
            port, _error = self._normalize_port(
                payload.get("exposed_port") or image_spec["default_exposed_port"]
            )
            port_holder = self._honeypot_repository.get_by_exposed_port(port)
            if port_holder is not None:
                port = self._allocate_port(image_spec["default_exposed_port"])

            container_name = str(payload.get("container_name") or "").strip() or self._generate_container_name(
                name=payload.get("name") or honeypot_id
            )
            item = self._honeypot_repository.create(
                honeypot_id=honeypot_id,
                name=str(payload.get("name") or honeypot_id).strip(),
                honeypot_type=honeypot_type,
                image_key=image_spec["key"],
                image_name=str(payload.get("image_name") or image_spec["image_name"]).strip(),
                container_name=container_name,
                host_ip=str(payload.get("host_ip") or "").strip() or None,
                bind_host="0.0.0.0",
                exposed_port=port,
                container_port=int(payload.get("container_port") or image_spec["container_port"]),
                honeypot_profile=str(payload.get("profile") or image_spec["profile"]).strip(),
                desired_state="running",
                runtime_status="running",
                runtime_meta={},
            )

        item.name = str(payload.get("name") or item.name).strip() or item.name
        item.honeypot_type = honeypot_type
        item.image_key = image_spec["key"]
        item.image_name = str(payload.get("image_name") or item.image_name or image_spec["image_name"]).strip()
        item.container_name = str(payload.get("container_name") or item.container_name).strip() or item.container_name
        item.container_port = int(payload.get("container_port") or item.container_port or image_spec["container_port"])
        item.honeypot_profile = str(payload.get("profile") or item.honeypot_profile or image_spec["profile"]).strip()
        item.host_ip = str(payload.get("host_ip") or item.host_ip or "").strip() or item.host_ip
        item.desired_state = str(payload.get("desired_state") or item.desired_state or "running").strip().lower()
        item.runtime_status = str(payload.get("status") or "running").strip().lower()
        item.container_id = str(payload.get("container_id") or item.container_id or "").strip() or item.container_id
        item.last_seen_ip = collector_ip
        item.last_error = None
        item.last_heartbeat_at = parse_iso_datetime(payload.get("heartbeat_at")) or datetime.now(timezone.utc)
        item.runtime_meta = {
            **dict(item.runtime_meta or {}),
            **dict(payload.get("meta") or {}),
        }
        self._honeypot_repository.save(item)
        return self._serialize(item), None

    def _serialize(self, item: HoneypotInstance) -> dict:
        return item.to_dict(timeout_seconds=self._heartbeat_timeout_seconds)

    def _sync_runtime_state(self, item: HoneypotInstance) -> HoneypotInstance:
        try:
            runtime = self._runtime_adapter.inspect_instance(item)
        except Exception as exc:  # noqa: BLE001
            item.last_error = str(exc)
            item.last_runtime_sync_at = datetime.now(timezone.utc)
            return self._honeypot_repository.save(item)

        self._apply_runtime_payload(item, runtime, persist=False)
        return self._honeypot_repository.save(item)

    def _apply_runtime_payload(self, item: HoneypotInstance, payload: dict, *, persist: bool = False) -> None:
        if payload.get("runtime_status"):
            item.runtime_status = str(payload["runtime_status"]).strip().lower()
        item.container_id = payload.get("container_id") or item.container_id
        item.host_ip = payload.get("host_ip") or item.host_ip
        item.last_error = payload.get("last_error")
        item.last_runtime_sync_at = payload.get("last_runtime_sync_at") or datetime.now(timezone.utc)
        item.runtime_meta = {
            **dict(item.runtime_meta or {}),
            **dict(payload.get("runtime_meta") or {}),
        }
        if persist:
            self._honeypot_repository.save(item)

    def _find_catalog_item(self, key: str | None) -> dict | None:
        key = str(key or "").strip()
        for item in self._CATALOG:
            if item["key"] == key:
                return dict(item)
        return None

    def _generate_honeypot_id(self) -> str:
        return f"hp-web-{uuid4().hex[:12]}"

    def _generate_container_name(self, *, name: str) -> str:
        base = re.sub(r"[^a-z0-9]+", "-", str(name or "honeypot").strip().lower()).strip("-")
        base = base or "honeypot"
        base = base[:36].rstrip("-")
        while True:
            candidate = f"mirage-{base}-{uuid4().hex[:6]}"
            if self._honeypot_repository.get_by_container_name(candidate) is None:
                return candidate

    def _normalize_port(self, value) -> tuple[int | None, str | None]:
        try:
            port = int(value)
        except (TypeError, ValueError):
            return None, "exposed_port 必须是有效端口"

        if port < 1 or port > 65535:
            return None, "exposed_port 必须在 1-65535 之间"
        return port, None

    def _allocate_port(self, start_port: int) -> int:
        candidate = max(int(start_port), 1024)
        while self._honeypot_repository.get_by_exposed_port(candidate) is not None:
            candidate += 1
        return candidate

    def _summarize(self, items: list[HoneypotInstance]) -> dict:
        summary = {
            "total": len(items),
            "running": 0,
            "stopped": 0,
            "online": 0,
            "stale": 0,
            "offline": 0,
        }
        for item in items:
            if item.runtime_status == "running":
                summary["running"] += 1
            if item.runtime_status in {"stopped", "exited", "missing"}:
                summary["stopped"] += 1

            heartbeat_state = item.heartbeat_state(timeout_seconds=self._heartbeat_timeout_seconds)
            if heartbeat_state in summary:
                summary[heartbeat_state] += 1
        return summary

    def _verify_started_instance(self, item: HoneypotInstance) -> str | None:
        if self._startup_verify_seconds <= 0:
            return None

        deadline = time.monotonic() + self._startup_verify_seconds
        current = item
        while True:
            current = self._sync_runtime_state(current)
            if current.runtime_status in {"exited", "missing", "stopped"}:
                current.desired_state = "stopped"
                current.last_error = f"蜜罐容器启动失败，当前状态: {current.runtime_status}"
                self._honeypot_repository.save(current)
                return current.last_error

            if (
                current.last_heartbeat_at is not None
                and current.heartbeat_state(timeout_seconds=self._heartbeat_timeout_seconds) == "online"
            ):
                current.last_error = None
                self._honeypot_repository.save(current)
                return None

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.5, remaining))

        timeout_message = f"蜜罐容器已启动，但在 {self._startup_verify_seconds} 秒内未收到心跳"
        try:
            runtime = self._runtime_adapter.stop_instance(current)
            current.desired_state = "stopped"
            self._apply_runtime_payload(current, runtime)
        except Exception as exc:  # noqa: BLE001
            current.last_error = str(exc)
            self._honeypot_repository.save(current)
            return timeout_message

        current.last_error = timeout_message
        self._honeypot_repository.save(current)
        return timeout_message

    def _control_plane_payload(self) -> dict:
        return {
            "controller_base_url": self._controller_base_url.rstrip("/"),
            "controller_public_base_url": self._controller_public_base_url.rstrip("/"),
            "control_token": self._control_token,
            "ingest_token": self._ingest_token,
        }
