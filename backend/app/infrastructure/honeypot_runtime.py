from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import SplitResult, urlsplit, urlunsplit

from app.models.honeypot_instance import HoneypotInstance

_DOCKER_BACKEND_ALIASES = {"backend-api", "honeypot-backend-api"}
_LOCALHOST_ALIASES = {"127.0.0.1", "localhost", "0.0.0.0", "::1"}
_HOST_GATEWAY_ALIAS = "host.docker.internal"


class HoneypotRuntimeAdapter:
    def health_status(self) -> dict:
        raise NotImplementedError

    def inspect_instance(self, instance: HoneypotInstance) -> dict:
        raise NotImplementedError

    def start_instance(self, instance: HoneypotInstance, image_spec: dict, control_plane: dict) -> dict:
        raise NotImplementedError

    def stop_instance(self, instance: HoneypotInstance) -> dict:
        raise NotImplementedError

    def delete_instance(self, instance: HoneypotInstance) -> dict:
        raise NotImplementedError


class NoopHoneypotRuntimeAdapter(HoneypotRuntimeAdapter):
    def health_status(self) -> dict:
        return {"status": "up", "message": "orchestration disabled (noop mode)"}

    def inspect_instance(self, instance: HoneypotInstance) -> dict:
        running = instance.desired_state == "running"
        return {
            "runtime_status": "running" if running else "stopped",
            "container_id": instance.container_id or f"noop-{instance.honeypot_id}",
            "host_ip": instance.host_ip or "127.0.0.1",
            "last_error": None,
            "runtime_meta": {"mode": "noop"},
            "last_runtime_sync_at": datetime.now(timezone.utc),
        }

    def start_instance(self, instance: HoneypotInstance, image_spec: dict, control_plane: dict) -> dict:
        result = self.inspect_instance(instance)
        result["runtime_status"] = "running"
        result["runtime_meta"] = {
            **dict(result.get("runtime_meta") or {}),
            "mode": "noop",
            "image": image_spec.get("image_name"),
            "controller_base_url": control_plane.get("controller_base_url"),
        }
        return result

    def stop_instance(self, instance: HoneypotInstance) -> dict:
        result = self.inspect_instance(instance)
        result["runtime_status"] = "stopped"
        return result

    def delete_instance(self, instance: HoneypotInstance) -> dict:
        return {"deleted": True}


class DockerHoneypotRuntimeAdapter(HoneypotRuntimeAdapter):
    def __init__(
        self,
        *,
        docker_host: str = "",
        docker_network: str = "miragetrap-net",
        add_host_gateway: bool = True,
        read_only_rootfs: bool = False,
        heartbeat_interval_seconds: int = 15,
    ):
        import docker

        self._docker = docker
        self._client = docker.DockerClient(base_url=docker_host) if docker_host else docker.from_env()
        self._docker_network = docker_network
        self._add_host_gateway = add_host_gateway
        self._read_only_rootfs = read_only_rootfs
        self._heartbeat_interval_seconds = heartbeat_interval_seconds

    def health_status(self) -> dict:
        try:
            self._client.ping()
            return {"status": "up", "message": "docker runtime reachable"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "down", "message": str(exc)}

    def inspect_instance(self, instance: HoneypotInstance) -> dict:
        container = self._get_container(instance.container_name)
        if container is None:
            return {
                "runtime_status": "missing",
                "container_id": None,
                "host_ip": None,
                "last_error": None,
                "runtime_meta": {"network": self._docker_network},
                "last_runtime_sync_at": datetime.now(timezone.utc),
            }

        container.reload()
        attrs = container.attrs or {}
        state = attrs.get("State") or {}
        network_settings = attrs.get("NetworkSettings") or {}
        networks = network_settings.get("Networks") or {}
        network_info = networks.get(self._docker_network) or next(iter(networks.values()), {})
        return {
            "runtime_status": str(state.get("Status") or container.status or "unknown").lower(),
            "container_id": container.id,
            "host_ip": network_info.get("IPAddress"),
            "last_error": state.get("Error") or None,
            "runtime_meta": {
                "network": self._docker_network,
                "network_aliases": list(network_info.get("Aliases") or []),
                "ports": network_settings.get("Ports") or {},
                "image": attrs.get("Config", {}).get("Image"),
            },
            "last_runtime_sync_at": datetime.now(timezone.utc),
        }

    def start_instance(self, instance: HoneypotInstance, image_spec: dict, control_plane: dict) -> dict:
        container = self._get_container(instance.container_name)
        environment = self._build_environment(instance, image_spec, control_plane)
        if container is None:
            container = self._run_container(instance, environment)
        else:
            container.reload()
            if self._should_recreate_container(container, instance, environment):
                self._remove_container(container)
                container = self._run_container(instance, environment)
            elif str(container.attrs.get("State", {}).get("Status") or container.status or "").lower() != "running":
                try:
                    container.start()
                except self._docker.errors.APIError as exc:
                    raise RuntimeError(str(exc)) from exc

        return self.inspect_instance(instance)

    def stop_instance(self, instance: HoneypotInstance) -> dict:
        container = self._get_container(instance.container_name)
        if container is not None:
            try:
                container.stop(timeout=5)
            except self._docker.errors.APIError as exc:
                raise RuntimeError(str(exc)) from exc

        result = self.inspect_instance(instance)
        result["runtime_status"] = "stopped"
        return result

    def delete_instance(self, instance: HoneypotInstance) -> dict:
        container = self._get_container(instance.container_name)
        if container is not None:
            try:
                container.remove(force=True)
            except self._docker.errors.APIError as exc:
                raise RuntimeError(str(exc)) from exc
        return {"deleted": True}

    def _build_environment(self, instance: HoneypotInstance, image_spec: dict, control_plane: dict) -> dict:
        controller_base_url = self._resolve_controller_base_url(control_plane)
        control_token = str(control_plane.get("control_token") or "")
        ingest_token = str(control_plane.get("ingest_token") or control_token)
        return {
            "WEB_HONEYPOT_PORT": str(instance.container_port),
            "INGEST_API_URL": f"{controller_base_url}/api/ingest/events",
            "HEARTBEAT_API_URL": f"{controller_base_url}/api/honeypots/heartbeat",
            "INGEST_TOKEN": ingest_token,
            "HONEYPOT_CONTROL_TOKEN": control_token,
            "HONEYPOT_ID": instance.honeypot_id,
            "HONEYPOT_NAME": instance.name,
            "HONEYPOT_IMAGE_KEY": instance.image_key,
            "HONEYPOT_IMAGE_NAME": instance.image_name,
            "HONEYPOT_CONTAINER_NAME": instance.container_name,
            "HONEYPOT_PROFILE": instance.honeypot_profile,
            "HONEYPOT_EXPOSED_PORT": str(instance.exposed_port),
            "HEARTBEAT_INTERVAL_SECONDS": str(self._heartbeat_interval_seconds),
        }

    def _resolve_controller_base_url(self, control_plane: dict) -> str:
        configured_url = str(
            control_plane.get("controller_public_base_url") or control_plane.get("controller_base_url") or ""
        ).rstrip("/")
        if not configured_url:
            return configured_url

        parsed = urlsplit(configured_url)
        hostname = str(parsed.hostname or "").strip().lower()
        if not hostname:
            return configured_url

        if hostname in _LOCALHOST_ALIASES:
            return self._replace_url_hostname(parsed, _HOST_GATEWAY_ALIAS)

        if hostname in _DOCKER_BACKEND_ALIASES and not self._is_backend_service_running():
            return self._replace_url_hostname(parsed, _HOST_GATEWAY_ALIAS)

        return configured_url

    def _replace_url_hostname(self, parsed: SplitResult, hostname: str) -> str:
        port = parsed.port
        netloc = f"{hostname}:{port}" if port else hostname
        return urlunsplit((parsed.scheme or "http", netloc, parsed.path, parsed.query, parsed.fragment)).rstrip("/")

    def _is_backend_service_running(self) -> bool:
        for container_name in _DOCKER_BACKEND_ALIASES:
            container = self._get_container(container_name)
            if container is None:
                continue

            container.reload()
            attrs = container.attrs or {}
            state = attrs.get("State") or {}
            if str(state.get("Status") or container.status or "").lower() != "running":
                continue

            if not self._docker_network:
                return True

            networks = (attrs.get("NetworkSettings") or {}).get("Networks") or {}
            if self._docker_network in networks:
                return True

        return False

    def _run_container(self, instance: HoneypotInstance, environment: dict):
        run_kwargs = {
            "name": instance.container_name,
            "detach": True,
            "ports": {f"{instance.container_port}/tcp": instance.exposed_port},
            "environment": environment,
            "labels": {
                "miragetrap.managed": "true",
                "miragetrap.honeypot_id": instance.honeypot_id,
                "miragetrap.honeypot_type": instance.honeypot_type,
            },
            "restart_policy": {"Name": "unless-stopped"},
            "read_only": self._read_only_rootfs,
        }
        if self._docker_network:
            run_kwargs["network"] = self._docker_network
        if self._add_host_gateway:
            run_kwargs["extra_hosts"] = {_HOST_GATEWAY_ALIAS: "host-gateway"}

        try:
            return self._client.containers.run(instance.image_name, **run_kwargs)
        except self._docker.errors.APIError as exc:
            if "host-gateway" in str(exc).lower() and run_kwargs.get("extra_hosts"):
                fallback_kwargs = dict(run_kwargs)
                fallback_kwargs.pop("extra_hosts", None)
                try:
                    return self._client.containers.run(instance.image_name, **fallback_kwargs)
                except self._docker.errors.APIError as fallback_exc:
                    raise RuntimeError(str(fallback_exc)) from fallback_exc
            raise RuntimeError(str(exc)) from exc

    def _should_recreate_container(self, container, instance: HoneypotInstance, expected_environment: dict) -> bool:
        attrs = container.attrs or {}
        config = attrs.get("Config") or {}
        if config.get("Image") != instance.image_name:
            return True
        if not self._environment_matches(config.get("Env") or [], expected_environment):
            return True
        if not self._ports_match(attrs, instance):
            return True
        if self._docker_network and not self._network_matches(attrs):
            return True
        return False

    def _environment_matches(self, env_items: list[str], expected: dict) -> bool:
        env_map = {}
        for item in env_items:
            if "=" not in str(item):
                continue
            key, value = str(item).split("=", 1)
            env_map[key] = value
        return all(env_map.get(key) == str(value) for key, value in expected.items())

    def _ports_match(self, attrs: dict, instance: HoneypotInstance) -> bool:
        ports = ((attrs.get("NetworkSettings") or {}).get("Ports") or {}).get(f"{instance.container_port}/tcp")
        if not ports:
            return False
        host_ports = {str(item.get("HostPort") or "") for item in ports if item}
        return str(instance.exposed_port) in host_ports

    def _network_matches(self, attrs: dict) -> bool:
        networks = ((attrs.get("NetworkSettings") or {}).get("Networks") or {})
        return self._docker_network in networks

    def _remove_container(self, container) -> None:
        try:
            container.remove(force=True)
        except self._docker.errors.APIError as exc:
            raise RuntimeError(str(exc)) from exc

    def _get_container(self, container_name: str):
        try:
            return self._client.containers.get(container_name)
        except self._docker.errors.NotFound:
            return None
        except self._docker.errors.APIError as exc:
            raise RuntimeError(str(exc)) from exc


def build_honeypot_runtime_adapter(config) -> HoneypotRuntimeAdapter:
    if not config.get("HONEYPOT_ORCHESTRATION_ENABLED", False):
        return NoopHoneypotRuntimeAdapter()

    return DockerHoneypotRuntimeAdapter(
        docker_host=config.get("HONEYPOT_DOCKER_HOST", ""),
        docker_network=config.get("HONEYPOT_DOCKER_NETWORK", "miragetrap-net"),
        add_host_gateway=config.get("HONEYPOT_DOCKER_ADD_HOST_GATEWAY", True),
        read_only_rootfs=config.get("HONEYPOT_DOCKER_READ_ONLY_ROOTFS", False),
        heartbeat_interval_seconds=config.get("HONEYPOT_HEARTBEAT_INTERVAL_SECONDS", 15),
    )
