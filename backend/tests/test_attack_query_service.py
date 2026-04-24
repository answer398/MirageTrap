import unittest

from app.services.attack_query_service import AttackQueryService


class FakeAttackEventRepository:
    def __init__(self) -> None:
        self.last_kwargs = None

    def list_paginated(self, **kwargs):
        self.last_kwargs = kwargs
        return {
            "items": [
                {
                    "id": 1,
                    "event_type": "web_sqli",
                    "request_content": '{"method":"GET","path":"/login","query_string":"","params":{},"headers":{},"body":"","raw_request":""}',
                    "threat_tags": ["sql_injection"],
                }
            ],
            "page": 1,
            "page_size": 20,
            "total": 1,
            "pages": 1,
        }

    def list_filtered(self, **kwargs):
        self.last_kwargs = kwargs

        class FakeEvent:
            def to_dict(self_inner):
                return {
                    "id": 2,
                    "created_at": "2026-04-22T12:00:00+00:00",
                    "source_ip": "198.51.100.10",
                    "country": "United States",
                    "city": "Ashburn",
                    "session_id": "sess_xxx",
                    "honeypot_type": "web",
                    "event_type": "web_sqli",
                    "risk_level": "high",
                    "risk_score": 88,
                    "request_content": '{"method":"POST","path":"/submit","query_string":"","params":{},"headers":{},"body":"id=1","raw_request":""}',
                    "threat_tags": ["sql_injection"],
                }

        return [FakeEvent()]


class FakeRiskEngineService:
    def describe_rules(self, rule_keys):
        return [{"key": item, "title": item} for item in rule_keys]


class AttackQueryServiceTestCase(unittest.TestCase):
    def test_list_attacks_passes_new_filters_to_repository(self):
        repository = FakeAttackEventRepository()
        service = AttackQueryService(
            event_repository=repository,
            risk_engine_service=FakeRiskEngineService(),
        )

        data = service.list_attacks(
            page=2,
            page_size=50,
            source_ip="198.51.100.10",
            honeypot_id="hp-web-123456",
            honeypot_type="web",
            risk_level="high",
            event_type="web_sqli",
            session_id="sess_xxx",
            keyword="union select",
            sort_by="risk_score",
            sort_dir="asc",
        )

        self.assertEqual(repository.last_kwargs["event_type"], "web_sqli")
        self.assertEqual(repository.last_kwargs["session_id"], "sess_xxx")
        self.assertEqual(repository.last_kwargs["honeypot_id"], "hp-web-123456")
        self.assertEqual(repository.last_kwargs["keyword"], "union select")
        self.assertEqual(repository.last_kwargs["sort_by"], "risk_score")
        self.assertEqual(repository.last_kwargs["sort_dir"], "asc")
        self.assertEqual(data["items"][0]["request_path"], "/login")
        self.assertEqual(data["items"][0]["request_preview"], "GET /login")

    def test_export_attacks_returns_csv_bytes(self):
        repository = FakeAttackEventRepository()
        service = AttackQueryService(
            event_repository=repository,
            risk_engine_service=FakeRiskEngineService(),
        )

        payload = service.export_attacks(
            source_ip="198.51.100.10",
            honeypot_id="hp-web-123456",
            sort_by="created_at",
            sort_dir="desc",
        )
        text = payload.decode("utf-8-sig")

        self.assertIn("source_ip", text)
        self.assertIn("honeypot_id", text)
        self.assertIn("198.51.100.10", text)
        self.assertIn("POST,/submit", text)
        self.assertIn("sql_injection", text)


if __name__ == "__main__":
    unittest.main()
