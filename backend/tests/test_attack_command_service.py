import json
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.services.attack_command_service import AttackCommandService


def build_event(*, event_id: int, session_id: str, created_at: datetime, risk_level: str, path: str):
    return SimpleNamespace(
        id=event_id,
        session_id=session_id,
        created_at=created_at,
        risk_level=risk_level,
        request_content=json.dumps(
            {
                "method": "GET",
                "path": path,
                "query_string": "",
                "params": {},
                "headers": {},
                "body": "",
                "raw_request": "",
            }
        ),
    )


class FakeAttackEventRepository:
    def __init__(self, events):
        self.events = {item.id: item for item in events}

    def list_by_ids(self, event_ids):
        return [self.events[item] for item in sorted(event_ids) if item in self.events]

    def delete_many(self, events):
        for item in events:
            self.events.pop(item.id, None)
        return len(events)

    def list_by_session(self, session_id):
        return sorted(
            [item for item in self.events.values() if item.session_id == session_id],
            key=lambda item: (item.created_at, item.id),
        )


class FakeAttackSessionRepository:
    def __init__(self, sessions):
        self.sessions = {item.session_id: item for item in sessions}
        self.deleted_ids = []

    def get_by_id(self, session_id):
        return self.sessions.get(session_id)

    def save(self, session):
        self.sessions[session.session_id] = session
        return session

    def delete(self, session):
        self.deleted_ids.append(session.session_id)
        self.sessions.pop(session.session_id, None)


class FakeEvidenceRepository:
    def __init__(self, mapping=None):
        self.mapping = mapping or {}

    def list_by_session(self, session_id):
        return list(self.mapping.get(session_id, []))


class AttackCommandServiceTestCase(unittest.TestCase):
    def test_bulk_delete_rebuilds_session_summary_and_risk(self):
        now = datetime.now(timezone.utc)
        session = SimpleNamespace(
            session_id="sess_keep",
            start_time=now - timedelta(minutes=6),
            end_time=now - timedelta(minutes=1),
            event_count=3,
            risk_level="critical",
            summary="stale summary",
            sample_count=0,
        )
        events = [
            build_event(
                event_id=1,
                session_id="sess_keep",
                created_at=now - timedelta(minutes=6),
                risk_level="medium",
                path="/health",
            ),
            build_event(
                event_id=2,
                session_id="sess_keep",
                created_at=now - timedelta(minutes=4),
                risk_level="critical",
                path="/admin",
            ),
            build_event(
                event_id=3,
                session_id="sess_keep",
                created_at=now - timedelta(minutes=1),
                risk_level="low",
                path="/login",
            ),
        ]

        service = AttackCommandService(
            event_repository=FakeAttackEventRepository(events),
            session_repository=FakeAttackSessionRepository([session]),
            evidence_repository=FakeEvidenceRepository(),
        )

        data, error = service.delete_attacks([2, 99])

        self.assertIsNone(error)
        self.assertEqual(data["deleted_count"], 1)
        self.assertEqual(data["missing_ids"], [99])
        self.assertEqual(data["session_updates"][0]["status"], "updated")
        self.assertEqual(session.event_count, 2)
        self.assertEqual(session.risk_level, "medium")
        self.assertEqual(session.start_time, events[0].created_at)
        self.assertEqual(session.end_time, events[2].created_at)
        self.assertEqual(session.summary, "GET /health\nGET /login")

    def test_delete_last_event_removes_session_without_evidence(self):
        now = datetime.now(timezone.utc)
        session = SimpleNamespace(
            session_id="sess_delete",
            start_time=now - timedelta(minutes=2),
            end_time=now - timedelta(minutes=2),
            event_count=1,
            risk_level="high",
            summary="GET /danger",
            sample_count=0,
        )
        events = [
            build_event(
                event_id=10,
                session_id="sess_delete",
                created_at=now - timedelta(minutes=2),
                risk_level="high",
                path="/danger",
            )
        ]
        sessions = FakeAttackSessionRepository([session])

        service = AttackCommandService(
            event_repository=FakeAttackEventRepository(events),
            session_repository=sessions,
            evidence_repository=FakeEvidenceRepository(),
        )

        data, error = service.delete_attack(10)

        self.assertIsNone(error)
        self.assertEqual(data["deleted_ids"], [10])
        self.assertEqual(data["session_updates"][0]["status"], "deleted")
        self.assertNotIn("sess_delete", sessions.sessions)
        self.assertEqual(sessions.deleted_ids, ["sess_delete"])

    def test_delete_last_event_keeps_empty_session_when_evidence_exists(self):
        now = datetime.now(timezone.utc)
        session = SimpleNamespace(
            session_id="sess_archive",
            start_time=now - timedelta(minutes=3),
            end_time=now - timedelta(minutes=1),
            event_count=1,
            risk_level="critical",
            summary="GET /archive",
            sample_count=2,
        )
        events = [
            build_event(
                event_id=20,
                session_id="sess_archive",
                created_at=now - timedelta(minutes=1),
                risk_level="critical",
                path="/archive",
            )
        ]

        service = AttackCommandService(
            event_repository=FakeAttackEventRepository(events),
            session_repository=FakeAttackSessionRepository([session]),
            evidence_repository=FakeEvidenceRepository({"sess_archive": [SimpleNamespace(id=1)]}),
        )

        data, error = service.delete_attack(20)

        self.assertIsNone(error)
        self.assertEqual(data["session_updates"][0]["status"], "emptied")
        self.assertEqual(session.event_count, 0)
        self.assertEqual(session.risk_level, "low")
        self.assertEqual(session.summary, "")
        self.assertEqual(session.sample_count, 0)


if __name__ == "__main__":
    unittest.main()
