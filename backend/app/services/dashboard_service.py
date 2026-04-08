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
            "today_attack_total": self._event_repository.count_total_since(day_start),
            "active_attack_ips": self._event_repository.count_unique_ip_since(day_start),
            "web_attack_total": self._event_repository.count_by_honeypot_since(day_start, "web"),
            "high_risk_total": self._event_repository.count_high_risk_since(day_start),
            "attack_type_count": self._event_repository.count_attack_types_since(day_start),
            "generated_at": now.isoformat(),
        }

    def get_global_map(self, *, start_time: datetime, limit: int = 20) -> dict:
        points = self._event_repository.top_map_regions(start_time=start_time, limit=limit)
        recent_events = self._event_repository.list_since(start_time=start_time, limit=100)

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
                    "region": item.region or "",
                    "city": item.city or "",
                    "honeypot_type": item.honeypot_type,
                    "event_type": item.event_type,
                    "risk_level": item.risk_level,
                    "request_preview": request_preview(parse_request_content(item.request_content)),
                }
                for item in recent_events[-50:]
            ],
            "summary": {
                "region_count": len(points),
                "attack_total": self._event_repository.count_total_since(start_time),
                "high_risk_total": self._event_repository.count_high_risk_since(start_time),
            },
        }

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

        events = self._event_repository.list_since(start_time=start_time, limit=10000)
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
            "items": self._event_repository.top_attackers(start_time=start_time, limit=limit),
        }

    def get_attack_type_distribution(self, *, start_time: datetime, limit: int = 20) -> dict:
        return {
            "window_start": start_time.isoformat(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "items": self._event_repository.attack_type_distribution(
                start_time=start_time,
                limit=limit,
            ),
        }
