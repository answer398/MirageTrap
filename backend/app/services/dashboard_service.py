import math
from datetime import datetime, timedelta, timezone

from app.repositories.attack_event_repository import AttackEventRepository
from app.utils.web_request import parse_request_content, request_preview


class DashboardService:
    def __init__(self, event_repository: AttackEventRepository):
        self._event_repository = event_repository

    def get_overview(self, *, start_time: datetime | None = None) -> dict:
        now = datetime.now(timezone.utc)
        effective_start_time = start_time or now.replace(hour=0, minute=0, second=0, microsecond=0)

        return {
            "today_attack_total": self._event_repository.count_total_since(
                effective_start_time,
                attack_only=True,
            ),
            "active_attack_ips": self._event_repository.count_unique_ip_since(
                effective_start_time,
                attack_only=True,
            ),
            "web_attack_total": self._event_repository.count_by_honeypot_since(
                effective_start_time,
                "web",
                attack_only=True,
            ),
            "high_risk_total": self._event_repository.count_high_risk_since(
                effective_start_time,
                attack_only=True,
            ),
            "attack_type_count": self._event_repository.count_attack_types_since(
                effective_start_time,
                attack_only=True,
            ),
            "window_start": effective_start_time.isoformat(),
            "generated_at": now.isoformat(),
        }

    def get_global_map(self, *, start_time: datetime, limit: int = 20) -> dict:
        points = self._event_repository.top_map_regions(
            start_time=start_time,
            limit=limit,
            attack_only=True,
        )
        recent_events = self._event_repository.list_since(
            start_time=start_time,
            limit=10000,
            attack_only=True,
        )
        points = self._attach_point_details(points=points, start_time=start_time)

        return {
            "window_start": start_time.isoformat(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "points": points,
            "recent_events": [
                {
                    "id": item.id,
                    "time": item.created_at.isoformat(),
                    "source_ip": item.source_ip,
                    "country": item.country or "unknown",
                    "country_code": item.country_code or None,
                    "region": item.region or "",
                    "region_code": item.region_code or None,
                    "city": item.city or "",
                    "latitude": item.latitude,
                    "longitude": item.longitude,
                    "honeypot_type": item.honeypot_type,
                    "event_type": item.event_type,
                    "risk_level": item.risk_level,
                    "request_preview": request_preview(parse_request_content(item.request_content)),
                }
                for item in recent_events[-50:]
            ],
            "summary": {
                "region_count": len(points),
                "attack_total": self._event_repository.count_total_since(start_time, attack_only=True),
                "high_risk_total": self._event_repository.count_high_risk_since(
                    start_time,
                    attack_only=True,
                ),
            },
        }

    def _attach_point_details(self, *, points: list[dict], start_time: datetime) -> list[dict]:
        detailed_points = []
        for point in points:
            detail = self._event_repository.point_activity_details(
                start_time=start_time,
                country=point.get("country"),
                region=point.get("region"),
                city=point.get("city"),
                latitude=point.get("latitude"),
                longitude=point.get("longitude"),
                attack_only=True,
            )

            detailed_points.append(
                {
                    **point,
                    "primary_source_ip": detail.get("primary_source_ip"),
                    "sample_source_ips": detail.get("sample_source_ips") or [],
                    "attack_types": detail.get("attack_types") or [],
                    "latest_event_type": detail.get("latest_event_type"),
                    "latest_risk_level": detail.get("latest_risk_level"),
                    "latest_attack_at": detail.get("latest_attack_at") or point.get("latest_attack_at"),
                    "latest_request_preview": (
                        request_preview(parse_request_content(detail.get("latest_request_content")))
                        if detail.get("latest_request_content")
                        else None
                    ),
                }
            )

        return detailed_points

    @staticmethod
    def _point_key(
        *,
        country: str | None,
        region: str | None,
        city: str | None,
        latitude,
        longitude,
    ) -> str:
        def normalize_coord(value) -> str:
            if value is None:
                return ""
            return f"{float(value):.6f}"

        return "|".join(
            [
                country or "unknown",
                region or "",
                city or "",
                normalize_coord(latitude),
                normalize_coord(longitude),
            ]
        )

    def get_trends(self, *, start_time: datetime, window_hours: int = 24) -> dict:
        current_hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        bucket_hours = self._resolve_trend_bucket_hours(window_hours)
        bucket_count = max(1, math.ceil(window_hours / bucket_hours))
        aligned_current_hour = current_hour.replace(
            hour=(current_hour.hour // bucket_hours) * bucket_hours
        )
        buckets = {}
        for offset in range(bucket_count):
            slot = aligned_current_hour - timedelta(hours=(bucket_count - 1 - offset) * bucket_hours)
            buckets[slot] = {
                "time": slot.isoformat(),
                "bucket_hours": bucket_hours,
                "total_attack_count": 0,
                "web_attack_count": 0,
                "high_risk_count": 0,
                "critical_count": 0,
            }

        events = self._event_repository.list_since(
            start_time=start_time,
            limit=10000,
            attack_only=True,
        )
        for item in events:
            event_time = item.created_at
            if event_time.tzinfo is None:
                event_time = event_time.replace(tzinfo=timezone.utc)
            event_time = event_time.astimezone(timezone.utc).replace(
                minute=0,
                second=0,
                microsecond=0,
            )
            slot = event_time.replace(hour=(event_time.hour // bucket_hours) * bucket_hours)
            if slot not in buckets:
                continue

            bucket = buckets[slot]
            bucket["total_attack_count"] += 1
            if item.honeypot_type == "web":
                bucket["web_attack_count"] += 1
            if item.risk_level in {"high", "critical"}:
                bucket["high_risk_count"] += 1
            if item.risk_level == "critical":
                bucket["critical_count"] += 1

        return {
            "window_start": start_time.isoformat(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "window_hours": window_hours,
            "bucket_hours": bucket_hours,
            "series": list(buckets.values()),
        }

    @staticmethod
    def _resolve_trend_bucket_hours(window_hours: int) -> int:
        if window_hours <= 24:
            return 1
        if window_hours <= 72:
            return 3
        if window_hours <= 168:
            return 6
        if window_hours <= 360:
            return 12
        return 24

    def get_top_attackers(self, *, start_time: datetime, limit: int = 20) -> dict:
        return {
            "window_start": start_time.isoformat(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "items": self._event_repository.top_attackers(
                start_time=start_time,
                limit=limit,
                attack_only=True,
            ),
        }

    def get_attack_type_distribution(self, *, start_time: datetime, limit: int = 20) -> dict:
        return {
            "window_start": start_time.isoformat(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "items": self._event_repository.attack_type_distribution(
                start_time=start_time,
                limit=limit,
                attack_only=True,
            ),
        }
