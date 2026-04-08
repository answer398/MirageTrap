from __future__ import annotations

import io
from pathlib import Path
from typing import Protocol


class ObjectStorageAdapter(Protocol):
    def put_object(
        self,
        *,
        object_key: str,
        data: bytes,
        content_type: str = "application/octet-stream",
    ) -> str | None:
        ...

    def stat_object(self, *, object_key: str) -> dict | None:
        ...

    def get_object(self, *, object_key: str) -> tuple[bytes | None, str | None]:
        ...

    def health_status(self) -> dict:
        ...


class LocalObjectStorageAdapter:
    def __init__(self, base_path: str):
        self._base_path = Path(base_path).resolve()

    def put_object(
        self,
        *,
        object_key: str,
        data: bytes,
        content_type: str = "application/octet-stream",
    ) -> str | None:
        try:
            target = self._base_path / object_key
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            return None
        except Exception as exc:  # noqa: BLE001
            return str(exc)

    def stat_object(self, *, object_key: str) -> dict | None:
        target = self._base_path / object_key
        if not target.exists():
            return None

        stat = target.stat()
        return {
            "size": stat.st_size,
            "path": str(target),
        }

    def get_object(self, *, object_key: str) -> tuple[bytes | None, str | None]:
        target = self._base_path / object_key
        if not target.exists():
            return None, "object not found"
        try:
            return target.read_bytes(), None
        except Exception as exc:  # noqa: BLE001
            return None, str(exc)

    def health_status(self) -> dict:
        try:
            self._base_path.mkdir(parents=True, exist_ok=True)
            writable = self._base_path.is_dir()
            return {
                "status": "up" if writable else "down",
                "driver": "local",
                "base_path": str(self._base_path),
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "status": "down",
                "driver": "local",
                "message": str(exc),
            }


class MinioObjectStorageAdapter:
    def __init__(
        self,
        *,
        endpoint: str,
        access_key: str,
        secret_key: str,
        bucket: str,
        secure: bool = False,
    ):
        self._endpoint = endpoint
        self._access_key = access_key
        self._secret_key = secret_key
        self._bucket = bucket
        self._secure = secure

    def put_object(
        self,
        *,
        object_key: str,
        data: bytes,
        content_type: str = "application/octet-stream",
    ) -> str | None:
        client, error = self._client()
        if error:
            return error

        try:
            self._ensure_bucket(client)
            stream = io.BytesIO(data)
            client.put_object(
                self._bucket,
                object_key,
                stream,
                length=len(data),
                content_type=content_type,
            )
            return None
        except Exception as exc:  # noqa: BLE001
            return str(exc)

    def stat_object(self, *, object_key: str) -> dict | None:
        client, error = self._client()
        if error:
            return None

        try:
            stat = client.stat_object(self._bucket, object_key)
            return {
                "size": stat.size,
                "etag": stat.etag,
            }
        except Exception:  # noqa: BLE001
            return None

    def get_object(self, *, object_key: str) -> tuple[bytes | None, str | None]:
        client, error = self._client()
        if error:
            return None, error

        try:
            response = client.get_object(self._bucket, object_key)
            try:
                data = response.read()
            finally:
                response.close()
                response.release_conn()
            return data, None
        except Exception as exc:  # noqa: BLE001
            return None, str(exc)

    def health_status(self) -> dict:
        client, error = self._client()
        if error:
            return {
                "status": "down",
                "driver": "minio",
                "message": error,
            }

        try:
            bucket_exists = client.bucket_exists(self._bucket)
            return {
                "status": "up" if bucket_exists else "down",
                "driver": "minio",
                "endpoint": self._endpoint,
                "bucket": self._bucket,
                "bucket_exists": bool(bucket_exists),
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "status": "down",
                "driver": "minio",
                "endpoint": self._endpoint,
                "bucket": self._bucket,
                "message": str(exc),
            }

    def _client(self):
        try:
            from minio import Minio  # type: ignore

            return (
                Minio(
                    self._endpoint,
                    access_key=self._access_key,
                    secret_key=self._secret_key,
                    secure=self._secure,
                ),
                None,
            )
        except ModuleNotFoundError:
            return None, "minio SDK 未安装，请先安装 requirements 并重启服务"
        except Exception as exc:  # noqa: BLE001
            return None, str(exc)

    def _ensure_bucket(self, client) -> None:
        if not client.bucket_exists(self._bucket):
            client.make_bucket(self._bucket)


def build_object_storage_adapter(config) -> ObjectStorageAdapter:
    driver = (config.get("EVIDENCE_STORAGE_DRIVER") or "local").strip().lower()
    if driver == "minio":
        return MinioObjectStorageAdapter(
            endpoint=config.get("MINIO_ENDPOINT", "127.0.0.1:9000"),
            access_key=config.get("MINIO_ACCESS_KEY", "minioadmin"),
            secret_key=config.get("MINIO_SECRET_KEY", "minioadmin"),
            bucket=config.get("MINIO_BUCKET", "miragetrap-evidence"),
            secure=config.get("MINIO_SECURE", False),
        )

    return LocalObjectStorageAdapter(
        base_path=config.get("EVIDENCE_LOCAL_PATH", "instance/evidence"),
    )
