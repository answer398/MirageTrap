from __future__ import annotations

from datetime import datetime, timezone

from app.models.honeypot_instance import HoneypotInstance


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
        read_only_rootfs: bool = False,
        heartbeat_interval_seconds: int = 15,
    ):
        import docker

        self._docker = docker
        self._client = docker.DockerClient(base_url=docker_host) if docker_host else docker.from_env()
        self._docker_network = docker_network
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
            "last_error": None,
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
        if container is None:
            run_kwargs = {
                "name": instance.container_name,
                "detach": True,
                "ports": {f"{instance.container_port}/tcp": instance.exposed_port},
                "environment": self._build_environment(instance, image_spec, control_plane),
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
            container = self._client.containers.run(instance.image_name, **run_kwargs)
        else:
            container.start()

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
        controller_base_url = str(control_plane.get("controller_base_url") or "").rstrip("/")
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
        read_only_rootfs=config.get("HONEYPOT_DOCKER_READ_ONLY_ROOTFS", False),
        heartbeat_interval_seconds=config.get("HONEYPOT_HEARTBEAT_INTERVAL_SECONDS", 15),
    )
