from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from app.repositories.attack_event_repository import AttackEventRepository
from app.utils.web_request import parse_request_content, request_preview


class DashboardService:
    def __init__(self, event_repository: AttackEventRepository):
        self._event_repository = event_repository

    def get_overview(self) -> dict:
        now = datetime.now(timezone.utc)
        day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

        return {
            "today_attack_total": self._event_repository.count_total_since(day_start, attack_only=True),
            "active_attack_ips": self._event_repository.count_unique_ip_since(day_start, attack_only=True),
            "web_attack_total": self._event_repository.count_by_honeypot_since(
                day_start,
                "web",
                attack_only=True,
            ),
            "high_risk_total": self._event_repository.count_high_risk_since(day_start, attack_only=True),
            "attack_type_count": self._event_repository.count_attack_types_since(
                day_start,
                attack_only=True,
            ),
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
        points = self._attach_point_details(points=points, events=recent_events)

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

    def _attach_point_details(self, *, points: list[dict], events: list) -> list[dict]:
        point_events = defaultdict(list)
        for item in events:
            point_events[
                self._point_key(
                    country=item.country,
                    region=item.region,
                    city=item.city,
                    latitude=item.latitude,
                    longitude=item.longitude,
                )
            ].append(item)

        detailed_points = []
        for point in points:
            grouped_events = point_events.get(
                self._point_key(
                    country=point.get("country"),
                    region=point.get("region"),
                    city=point.get("city"),
                    latitude=point.get("latitude"),
                    longitude=point.get("longitude"),
                ),
                [],
            )
            ip_counter = Counter(item.source_ip for item in grouped_events if item.source_ip)
            type_counter = Counter(item.event_type for item in grouped_events if item.event_type)
            latest_event = grouped_events[-1] if grouped_events else None

            detailed_points.append(
                {
                    **point,
                    "primary_source_ip": ip_counter.most_common(1)[0][0] if ip_counter else None,
                    "sample_source_ips": [ip for ip, _ in ip_counter.most_common(3)],
                    "attack_types": [
                        {
                            "event_type": event_type,
                            "attack_count": int(attack_count),
                        }
                        for event_type, attack_count in type_counter.most_common(3)
                    ],
                    "latest_event_type": latest_event.event_type if latest_event else None,
                    "latest_risk_level": latest_event.risk_level if latest_event else None,
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

    def get_trends(self, *, start_time: datetime, bucket_hours: int = 24) -> dict:
        current_hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        buckets = {}
        for offset in range(bucket_hours):
            slot = current_hour.replace(minute=0, second=0, microsecond=0)
            slot = slot - timedelta(hours=(bucket_hours - 1 - offset))
            buckets[slot] = {
                "time": slot.isoformat(),
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
            slot = event_time.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
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
            "series": list(buckets.values()),
        }

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
