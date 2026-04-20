import json
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.services.dashboard_service import DashboardService


def build_request_content(*, method: str = "GET", path: str = "/", query_string: str = "") -> str:
    return json.dumps(
        {
            "method": method,
            "path": path,
            "query_string": query_string,
            "params": {},
            "headers": {},
            "body": "",
            "raw_request": "",
        }
    )


class FakeAttackEventRepository:
    def __init__(self) -> None:
        self.calls = []
        self.attack_event = SimpleNamespace(
            id=7,
            created_at=datetime.now(timezone.utc) - timedelta(minutes=5),
            source_ip="198.51.100.10",
            country="United States",
            country_code="US",
            region="Virginia",
            region_code="VA",
            city="Ashburn",
            latitude=39.0438,
            longitude=-77.4874,
            honeypot_type="web",
            event_type="web_sqli",
            risk_level="high",
            request_content=build_request_content(
                path="/product",
                query_string="id=1%20UNION%20SELECT%201,2--",
            ),
        )

    def count_total_since(self, start_time, *, attack_only=False):
        self.calls.append(("count_total_since", attack_only))
        return 6 if attack_only else 66

    def count_unique_ip_since(self, start_time, *, attack_only=False):
        self.calls.append(("count_unique_ip_since", attack_only))
        return 3 if attack_only else 33

    def count_by_honeypot_since(self, start_time, honeypot_type, *, attack_only=False):
        self.calls.append(("count_by_honeypot_since", honeypot_type, attack_only))
        return 5 if attack_only else 55

    def count_high_risk_since(self, start_time, *, attack_only=False):
        self.calls.append(("count_high_risk_since", attack_only))
        return 2 if attack_only else 22

    def count_attack_types_since(self, start_time, *, attack_only=False):
        self.calls.append(("count_attack_types_since", attack_only))
        return 4 if attack_only else 44

    def list_since(self, start_time, limit=1000, *, attack_only=False):
        self.calls.append(("list_since", limit, attack_only))
        return [self.attack_event] if attack_only else []

    def top_map_regions(self, *, start_time, limit=20, attack_only=False):
        self.calls.append(("top_map_regions", limit, attack_only))
        return [
            {
                "country": "United States",
                "country_code": "US",
                "region": "Virginia",
                "region_code": "VA",
                "city": "Ashburn",
                "latitude": 39.0438,
                "longitude": -77.4874,
                "attack_count": 6,
                "unique_ip_count": 3,
                "high_risk_count": 2,
                "latest_attack_at": self.attack_event.created_at.isoformat(),
            }
        ]

    def top_attackers(self, *, start_time, limit=20, attack_only=False):
        self.calls.append(("top_attackers", limit, attack_only))
        return [{"source_ip": "198.51.100.10", "attack_count": 6}]

    def attack_type_distribution(self, *, start_time, limit=20, attack_only=False):
        self.calls.append(("attack_type_distribution", limit, attack_only))
        return [{"event_type": "web_sqli", "attack_count": 6}]


class DashboardServiceTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = FakeAttackEventRepository()
        self.service = DashboardService(event_repository=self.repository)

    def test_overview_counts_only_attack_events(self):
        data = self.service.get_overview()

        self.assertEqual(data["today_attack_total"], 6)
        self.assertEqual(data["active_attack_ips"], 3)
        self.assertEqual(data["web_attack_total"], 5)
        self.assertEqual(data["high_risk_total"], 2)
        self.assertEqual(data["attack_type_count"], 4)
        self.assertIn(("count_total_since", True), self.repository.calls)
        self.assertIn(("count_unique_ip_since", True), self.repository.calls)
        self.assertIn(("count_by_honeypot_since", "web", True), self.repository.calls)
        self.assertIn(("count_high_risk_since", True), self.repository.calls)
        self.assertIn(("count_attack_types_since", True), self.repository.calls)

    def test_global_map_excludes_normal_requests(self):
        start_time = datetime.now(timezone.utc) - timedelta(hours=24)

        data = self.service.get_global_map(start_time=start_time, limit=12)

        self.assertEqual(len(data["points"]), 1)
        self.assertEqual(len(data["recent_events"]), 1)
        self.assertEqual(data["recent_events"][0]["event_type"], "web_sqli")
        self.assertEqual(data["summary"]["attack_total"], 6)
        self.assertIn(("top_map_regions", 12, True), self.repository.calls)
        self.assertIn(("list_since", 100, True), self.repository.calls)
        self.assertIn(("count_total_since", True), self.repository.calls)

    def test_trends_reads_attack_events_only(self):
        start_time = datetime.now(timezone.utc) - timedelta(hours=6)

        data = self.service.get_trends(start_time=start_time, bucket_hours=6)

        self.assertEqual(len(data["series"]), 6)
        self.assertIn(("list_since", 10000, True), self.repository.calls)
        self.assertEqual(sum(item["total_attack_count"] for item in data["series"]), 1)

    def test_top_attackers_and_attack_type_distribution_use_attack_only(self):
        start_time = datetime.now(timezone.utc) - timedelta(hours=24)

        top_attackers = self.service.get_top_attackers(start_time=start_time, limit=8)
        attack_types = self.service.get_attack_type_distribution(start_time=start_time, limit=8)

        self.assertEqual(top_attackers["items"][0]["source_ip"], "198.51.100.10")
        self.assertEqual(attack_types["items"][0]["event_type"], "web_sqli")
        self.assertIn(("top_attackers", 8, True), self.repository.calls)
        self.assertIn(("attack_type_distribution", 8, True), self.repository.calls)


if __name__ == "__main__":
    unittest.main()
