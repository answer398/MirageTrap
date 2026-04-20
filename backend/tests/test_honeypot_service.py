from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch
import unittest

from app.services.honeypot_service import HoneypotService


class FakeHoneypotInstance:
    def __init__(self):
        self.id = 1
        self.honeypot_id = "hp-web-test-001"
        self.name = "demo-honeypot"
        self.honeypot_type = "web"
        self.image_key = "web_portal"
        self.image_name = "miragetrap/web-honeypot:latest"
        self.container_name = "mirage-demo-001"
        self.bind_host = "0.0.0.0"
        self.exposed_port = 18080
        self.container_port = 80
        self.honeypot_profile = "portal"
        self.desired_state = "stopped"
        self.runtime_status = "stopped"
        self.container_id = None
        self.host_ip = None
        self.last_heartbeat_at = None
        self.last_runtime_sync_at = None
        self.last_seen_ip = None
        self.last_error = None
        self.runtime_meta = {}
        self.created_at = datetime.now(timezone.utc)
        self.updated_at = self.created_at

    def heartbeat_state(self, timeout_seconds: int = 45) -> str:
        if self.runtime_status in {"stopped", "exited", "missing"}:
            return "offline"
        if self.last_heartbeat_at is None:
            return "unknown"
        return "online"

    def to_dict(self, timeout_seconds: int = 45) -> dict:
        return {
            "id": self.id,
            "honeypot_id": self.honeypot_id,
            "name": self.name,
            "runtime_status": self.runtime_status,
            "heartbeat_state": self.heartbeat_state(timeout_seconds=timeout_seconds),
            "last_error": self.last_error,
        }


class FakeHoneypotRepository:
    def __init__(self, item):
        self.item = item

    def get_by_id(self, instance_id: int):
        if instance_id == self.item.id:
            return self.item
        return None

    def save(self, instance):
        self.item = instance
        return instance


class FakeRuntimeAdapter:
    def __init__(self, *, emit_heartbeat: bool):
        self.emit_heartbeat = emit_heartbeat
        self.inspect_calls = 0
        self.stop_calls = 0

    def start_instance(self, instance, image_spec: dict, control_plane: dict) -> dict:
        return {
            "runtime_status": "running",
            "container_id": "container-001",
            "host_ip": "172.20.0.10",
            "last_error": None,
            "runtime_meta": {"network": "miragetrap-net"},
            "last_runtime_sync_at": datetime.now(timezone.utc),
        }

    def inspect_instance(self, instance) -> dict:
        self.inspect_calls += 1
        if self.emit_heartbeat and self.inspect_calls >= 1:
            instance.last_heartbeat_at = datetime.now(timezone.utc)
        return {
            "runtime_status": "running",
            "container_id": "container-001",
            "host_ip": "172.20.0.10",
            "last_error": None,
            "runtime_meta": {"network": "miragetrap-net"},
            "last_runtime_sync_at": datetime.now(timezone.utc),
        }

    def stop_instance(self, instance) -> dict:
        self.stop_calls += 1
        return {
            "runtime_status": "stopped",
            "container_id": "container-001",
            "host_ip": "172.20.0.10",
            "last_error": None,
            "runtime_meta": {"network": "miragetrap-net"},
            "last_runtime_sync_at": datetime.now(timezone.utc),
        }


class HoneypotServiceStartVerificationTestCase(unittest.TestCase):
    def make_service(self, runtime_adapter, *, startup_verify_seconds: int = 1):
        return HoneypotService(
            honeypot_repository=FakeHoneypotRepository(FakeHoneypotInstance()),
            runtime_adapter=runtime_adapter,
            controller_base_url="http://backend-api:15000",
            controller_public_base_url="",
            control_token="control-token",
            ingest_token="ingest-token",
            heartbeat_timeout_seconds=45,
            startup_verify_seconds=startup_verify_seconds,
        )

    def test_start_instance_returns_success_after_first_heartbeat(self):
        service = self.make_service(FakeRuntimeAdapter(emit_heartbeat=True))

        data, error, status_code = service.start_instance(1)

        self.assertIsNone(error)
        self.assertIsNone(status_code)
        self.assertEqual(data["runtime_status"], "running")
        self.assertEqual(data["heartbeat_state"], "online")

    def test_start_instance_fails_when_heartbeat_is_not_received(self):
        runtime = FakeRuntimeAdapter(emit_heartbeat=False)
        service = self.make_service(runtime, startup_verify_seconds=1)

        with patch("app.services.honeypot_service.time.sleep", return_value=None), patch(
            "app.services.honeypot_service.time.monotonic",
            side_effect=[0.0, 0.6, 1.2],
        ):
            data, error, status_code = service.start_instance(1)

        self.assertIsNone(data)
        self.assertEqual(status_code, 502)
        self.assertIn("未收到心跳", error)
        self.assertEqual(runtime.stop_calls, 1)
        self.assertEqual(service._honeypot_repository.item.runtime_status, "stopped")
        self.assertEqual(service._honeypot_repository.item.desired_state, "stopped")


if __name__ == "__main__":
    unittest.main()
