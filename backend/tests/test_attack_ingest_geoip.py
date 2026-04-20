from datetime import datetime, timezone
import unittest

from app.services.attack_ingest_service import AttackIngestService


class FakeEvent:
    def __init__(self, payload: dict):
        self._payload = payload
        self.id = 1
        self.created_at = payload.get("created_at") or datetime.now(timezone.utc)

    def to_dict(self):
        return dict(self._payload)


class FakeEventRepository:
    def __init__(self):
        self.created = []

    def create(self, **kwargs):
        self.created.append(kwargs)
        return FakeEvent(kwargs)


class FakeSession:
    def __init__(self):
        self.session_id = "sess_test"

    def to_dict(self):
        return {"session_id": self.session_id}


class FakeSessionService:
    def resolve_session(self, **kwargs):
        return FakeSession()

    def apply_event(self, **kwargs):
        return FakeSession()


class FakeRiskEngineService:
    def evaluate(self, **kwargs):
        return {
            "risk_score": 10,
            "risk_level": "low",
            "matched_rules": [],
            "detected_event_type": "web_req",
        }

    def describe_rules(self, rule_keys):
        return []


class StaticGeoIPLookup:
    def __init__(self, result: dict | None):
        self._result = result

    def lookup_ip(self, ip_address_text: str):
        return self._result


class AttackIngestGeoIPTestCase(unittest.TestCase):
    def make_service(self, lookup_result):
        repository = FakeEventRepository()
        service = AttackIngestService(
            event_repository=repository,
            session_service=FakeSessionService(),
            risk_engine_service=FakeRiskEngineService(),
            geoip_lookup=StaticGeoIPLookup(lookup_result),
        )
        return service, repository

    def test_prefers_geoip_lookup_over_payload_geo(self):
        service, repository = self.make_service(
            {
                "country": "Japan",
                "country_code": "JP",
                "region": "Tokyo",
                "region_code": "13",
                "city": "Tokyo",
                "timezone": "Asia/Tokyo",
                "latitude": 35.6895,
                "longitude": 139.6917,
                "accuracy_radius": 20,
                "asn": "2516",
                "asn_org": "KDDI CORPORATION",
                "geo_source": "maxmind-geolite2",
                "is_private": False,
            }
        )

        _result, error = service.ingest_event(
            payload={
                "event_type": "web_req",
                "honeypot_type": "web",
                "path": "/search",
                "country": "unknown",
                "region": "",
                "city": "",
            },
            collector_ip="8.8.8.8",
        )

        self.assertIsNone(error)
        event = repository.created[-1]
        self.assertEqual(event["country"], "Japan")
        self.assertEqual(event["country_code"], "JP")
        self.assertEqual(event["region"], "Tokyo")
        self.assertEqual(event["city"], "Tokyo")
        self.assertEqual(event["timezone"], "Asia/Tokyo")
        self.assertEqual(event["latitude"], 35.6895)
        self.assertEqual(event["longitude"], 139.6917)
        self.assertEqual(event["asn"], "2516")
        self.assertEqual(event["asn_org"], "KDDI CORPORATION")
        self.assertEqual(event["geo_source"], "maxmind-geolite2")

    def test_marks_private_ip_without_fake_geo(self):
        service, repository = self.make_service(
            {
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
            }
        )

        _result, error = service.ingest_event(
            payload={
                "event_type": "web_req",
                "honeypot_type": "web",
                "path": "/status",
            },
            collector_ip="192.168.1.10",
        )

        self.assertIsNone(error)
        event = repository.created[-1]
        self.assertEqual(event["country"], "private")
        self.assertEqual(event["region"], "local")
        self.assertEqual(event["city"], "local")
        self.assertEqual(event["geo_source"], "private")
        self.assertIsNone(event["latitude"])
        self.assertIsNone(event["longitude"])


if __name__ == "__main__":
    unittest.main()
