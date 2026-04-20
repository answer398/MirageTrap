from types import SimpleNamespace
import unittest

from app.infrastructure.honeypot_runtime import DockerHoneypotRuntimeAdapter


class FakeDockerErrors:
    class NotFound(Exception):
        pass

    class APIError(Exception):
        pass


class FakeContainer:
    def __init__(
        self,
        name: str,
        *,
        image: str = "miragetrap/web-honeypot:latest",
        env: dict | None = None,
        status: str = "exited",
        exposed_port: int = 18080,
        container_port: int = 80,
        network: str = "miragetrap-net",
    ):
        self.name = name
        self.id = f"{name}-id"
        self.status = status
        self.removed = False
        self.started = False
        self.attrs = {
            "Config": {
                "Image": image,
                "Env": [f"{key}={value}" for key, value in (env or {}).items()],
            },
            "State": {
                "Status": status,
                "Error": "",
            },
            "NetworkSettings": {
                "Networks": {
                    network: {
                        "IPAddress": "172.20.0.10",
                        "Aliases": [name],
                    }
                }
                if network
                else {},
                "Ports": {
                    f"{container_port}/tcp": [
                        {
                            "HostIp": "0.0.0.0",
                            "HostPort": str(exposed_port),
                        }
                    ]
                },
            },
        }

    def reload(self):
        return None

    def start(self):
        self.started = True
        self.status = "running"
        self.attrs["State"]["Status"] = "running"

    def remove(self, force: bool = False):
        self.removed = force


class FakeContainersAPI:
    def __init__(self, containers: dict[str, FakeContainer], errors):
        self._containers = containers
        self._errors = errors
        self.run_calls: list[tuple[str, dict]] = []

    def get(self, name: str):
        if name in self._containers:
            return self._containers[name]
        raise self._errors.NotFound()

    def run(self, image: str, **kwargs):
        self.run_calls.append((image, kwargs))
        container_port = int(str(next(iter(kwargs["ports"]))).split("/", 1)[0])
        exposed_port = int(next(iter(kwargs["ports"].values())))
        container = FakeContainer(
            kwargs["name"],
            image=image,
            env=kwargs.get("environment") or {},
            status="running",
            exposed_port=exposed_port,
            container_port=container_port,
            network=kwargs.get("network") or "",
        )
        self._containers[kwargs["name"]] = container
        return container


def make_instance(**overrides):
    defaults = {
        "honeypot_id": "hp-web-test-001",
        "name": "demo-honeypot",
        "honeypot_type": "web",
        "image_key": "web_portal",
        "image_name": "miragetrap/web-honeypot:latest",
        "container_name": "mirage-demo-001",
        "honeypot_profile": "portal",
        "container_port": 80,
        "exposed_port": 18080,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def make_control_plane(base_url: str, public_base_url: str = "") -> dict:
    return {
        "controller_base_url": base_url,
        "controller_public_base_url": public_base_url,
        "control_token": "control-token",
        "ingest_token": "ingest-token",
    }


def make_adapter(containers: dict[str, FakeContainer] | None = None) -> DockerHoneypotRuntimeAdapter:
    adapter = DockerHoneypotRuntimeAdapter.__new__(DockerHoneypotRuntimeAdapter)
    adapter._docker = SimpleNamespace(errors=FakeDockerErrors)
    adapter._docker_network = "miragetrap-net"
    adapter._add_host_gateway = True
    adapter._read_only_rootfs = False
    adapter._heartbeat_interval_seconds = 15
    adapter._client = SimpleNamespace(
        containers=FakeContainersAPI(containers or {}, FakeDockerErrors),
    )
    return adapter


class HoneypotRuntimeAdapterTestCase(unittest.TestCase):
    def test_resolves_local_backend_url_through_host_gateway(self):
        adapter = make_adapter()
        environment = adapter._build_environment(
            make_instance(),
            {},
            make_control_plane("http://127.0.0.1:15000"),
        )

        self.assertEqual(environment["INGEST_API_URL"], "http://host.docker.internal:15000/api/ingest/events")
        self.assertEqual(
            environment["HEARTBEAT_API_URL"],
            "http://host.docker.internal:15000/api/honeypots/heartbeat",
        )

    def test_falls_back_to_host_gateway_when_backend_container_is_not_running(self):
        adapter = make_adapter()
        environment = adapter._build_environment(
            make_instance(),
            {},
            make_control_plane("http://backend-api:15000"),
        )

        self.assertEqual(environment["HEARTBEAT_API_URL"], "http://host.docker.internal:15000/api/honeypots/heartbeat")

    def test_keeps_backend_service_url_when_backend_container_is_running(self):
        backend_container = FakeContainer("backend-api", status="running", network="miragetrap-net")
        adapter = make_adapter({"backend-api": backend_container})
        environment = adapter._build_environment(
            make_instance(),
            {},
            make_control_plane("http://backend-api:15000"),
        )

        self.assertEqual(environment["HEARTBEAT_API_URL"], "http://backend-api:15000/api/honeypots/heartbeat")

    def test_start_recreates_container_when_runtime_env_has_changed(self):
        instance = make_instance()
        stale_container = FakeContainer(
            instance.container_name,
            env={
                "WEB_HONEYPOT_PORT": "80",
                "INGEST_API_URL": "http://backend-api:15000/api/ingest/events",
                "HEARTBEAT_API_URL": "http://backend-api:15000/api/honeypots/heartbeat",
                "INGEST_TOKEN": "ingest-token",
                "HONEYPOT_CONTROL_TOKEN": "control-token",
                "HONEYPOT_ID": instance.honeypot_id,
                "HONEYPOT_NAME": instance.name,
                "HONEYPOT_IMAGE_KEY": instance.image_key,
                "HONEYPOT_IMAGE_NAME": instance.image_name,
                "HONEYPOT_CONTAINER_NAME": instance.container_name,
                "HONEYPOT_PROFILE": instance.honeypot_profile,
                "HONEYPOT_EXPOSED_PORT": str(instance.exposed_port),
                "HEARTBEAT_INTERVAL_SECONDS": "15",
            },
            status="exited",
            exposed_port=instance.exposed_port,
            container_port=instance.container_port,
        )
        adapter = make_adapter({instance.container_name: stale_container})

        result = adapter.start_instance(
            instance,
            {},
            make_control_plane("http://127.0.0.1:15000"),
        )

        self.assertTrue(stale_container.removed)
        self.assertEqual(len(adapter._client.containers.run_calls), 1)
        _image, kwargs = adapter._client.containers.run_calls[0]
        self.assertEqual(
            kwargs["environment"]["HEARTBEAT_API_URL"],
            "http://host.docker.internal:15000/api/honeypots/heartbeat",
        )
        self.assertEqual(kwargs["extra_hosts"], {"host.docker.internal": "host-gateway"})
        self.assertEqual(result["runtime_status"], "running")


if __name__ == "__main__":
    unittest.main()
