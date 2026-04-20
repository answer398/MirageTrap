from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Protocol


class GeoIPLookupAdapter(Protocol):
    def lookup_ip(self, ip_address_text: str) -> dict | None:
        ...

    def health_status(self) -> dict:
        ...


class NoopGeoIPLookupAdapter:
    def __init__(self, *, enabled: bool = False, reason: str = "geoip disabled"):
        self._enabled = enabled
        self._reason = reason

    def lookup_ip(self, ip_address_text: str) -> dict | None:
        ip_obj = _parse_ip(ip_address_text)
        if ip_obj is None:
            return None
        if not ip_obj.is_global:
            return _private_lookup_result(ip_address_text)
        return None

    def health_status(self) -> dict:
        return {
            "status": "up" if not self._enabled else "down",
            "driver": "geoip-noop",
            "message": self._reason,
        }


class MaxMindGeoIPLookupAdapter:
    def __init__(
        self,
        *,
        city_db_path: str,
        asn_db_path: str,
    ):
        self._city_db_path = Path(city_db_path).resolve()
        self._asn_db_path = Path(asn_db_path).resolve()
        self._city_reader = None
        self._asn_reader = None
        self._init_error = None
        self._init_readers()

    def lookup_ip(self, ip_address_text: str) -> dict | None:
        ip_obj = _parse_ip(ip_address_text)
        if ip_obj is None:
            return None
        if not ip_obj.is_global:
            return _private_lookup_result(ip_address_text)

        result = {
            "country": None,
            "country_code": None,
            "region": None,
            "region_code": None,
            "city": None,
            "timezone": None,
            "latitude": None,
            "longitude": None,
            "accuracy_radius": None,
            "asn": None,
            "asn_org": None,
            "geo_source": "maxmind-geolite2",
            "is_private": False,
        }

        if self._city_reader is not None:
            city_response = self._safe_city_lookup(ip_address_text)
            if city_response is not None:
                location = city_response.location
                subdivision = city_response.subdivisions.most_specific
                result.update(
                    {
                        "country": city_response.country.name or city_response.registered_country.name,
                        "country_code": city_response.country.iso_code or city_response.registered_country.iso_code,
                        "region": subdivision.name,
                        "region_code": subdivision.iso_code,
                        "city": city_response.city.name,
                        "timezone": location.time_zone,
                        "latitude": location.latitude,
                        "longitude": location.longitude,
                        "accuracy_radius": location.accuracy_radius,
                    }
                )

        if self._asn_reader is not None:
            asn_response = self._safe_asn_lookup(ip_address_text)
            if asn_response is not None:
                result.update(
                    {
                        "asn": str(asn_response.autonomous_system_number)
                        if asn_response.autonomous_system_number is not None
                        else None,
                        "asn_org": asn_response.autonomous_system_organization,
                    }
                )

        if all(result.get(key) is None for key in ("country", "city", "latitude", "longitude", "asn")):
            return None
        return result

    def health_status(self) -> dict:
        if self._init_error:
            return {
                "status": "down",
                "driver": "maxmind-geolite2",
                "message": self._init_error,
                "city_db_path": str(self._city_db_path),
                "asn_db_path": str(self._asn_db_path),
            }

        city_exists = self._city_reader is not None
        asn_exists = self._asn_reader is not None
        status = "up" if city_exists and asn_exists else "degraded" if city_exists or asn_exists else "down"
        message = "GeoLite2 databases loaded"
        if status == "degraded":
            message = "GeoLite2 database partially loaded"
        elif status == "down":
            message = "GeoLite2 databases unavailable"

        return {
            "status": status,
            "driver": "maxmind-geolite2",
            "message": message,
            "city_db_path": str(self._city_db_path),
            "asn_db_path": str(self._asn_db_path),
            "city_db_loaded": city_exists,
            "asn_db_loaded": asn_exists,
        }

    def _init_readers(self) -> None:
        try:
            import geoip2.database
        except ModuleNotFoundError:
            self._init_error = "geoip2 SDK 未安装，请先安装 backend/requirements.txt"
            return
        except Exception as exc:  # noqa: BLE001
            self._init_error = str(exc)
            return

        errors = []
        if self._city_db_path.is_file():
            self._city_reader = geoip2.database.Reader(str(self._city_db_path))
        else:
            errors.append(f"city database not found: {self._city_db_path}")

        if self._asn_db_path.is_file():
            self._asn_reader = geoip2.database.Reader(str(self._asn_db_path))
        else:
            errors.append(f"asn database not found: {self._asn_db_path}")

        if errors and self._city_reader is None and self._asn_reader is None:
            self._init_error = "; ".join(errors)

    def _safe_city_lookup(self, ip_address_text: str):
        try:
            import geoip2.errors

            return self._city_reader.city(ip_address_text)
        except geoip2.errors.AddressNotFoundError:
            return None
        except Exception:  # noqa: BLE001
            return None

    def _safe_asn_lookup(self, ip_address_text: str):
        try:
            import geoip2.errors

            return self._asn_reader.asn(ip_address_text)
        except geoip2.errors.AddressNotFoundError:
            return None
        except Exception:  # noqa: BLE001
            return None


def build_geoip_lookup_adapter(config) -> GeoIPLookupAdapter:
    if not config.get("GEOIP_ENABLED", False):
        return NoopGeoIPLookupAdapter(enabled=False, reason="GeoIP disabled")

    return MaxMindGeoIPLookupAdapter(
        city_db_path=config.get("GEOIP_CITY_DB_PATH", "instance/geoip/GeoLite2-City.mmdb"),
        asn_db_path=config.get("GEOIP_ASN_DB_PATH", "instance/geoip/GeoLite2-ASN.mmdb"),
    )


def _parse_ip(ip_address_text: str):
    try:
        return ipaddress.ip_address(str(ip_address_text).strip())
    except ValueError:
        return None


def _private_lookup_result(ip_address_text: str) -> dict:
    return {
        "country": "private",
        "country_code": "PRIVATE",
        "region": "local",
        "region_code": "LOCAL",
        "city": "local",
        "timezone": None,
        "latitude": None,
        "longitude": None,
        "accuracy_radius": 0,
        "asn": None,
        "asn_org": None,
        "geo_source": "private",
        "is_private": True,
        "source_ip": ip_address_text,
    }
