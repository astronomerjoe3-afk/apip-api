from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.routers import student_support
from app.schemas.support import HelpRequestCreateIn


class _FakeDocSnapshot:
    def __init__(self, doc_id: str, payload: dict):
        self.id = doc_id
        self._payload = payload
        self.exists = bool(payload)

    def to_dict(self) -> dict:
        return dict(self._payload)


class _FakeDocRef:
    def __init__(self, store: dict[str, dict], doc_id: str):
        self._store = store
        self.id = doc_id

    def get(self):
        payload = self._store.get(self.id)
        return _FakeDocSnapshot(self.id, payload or {})

    def set(self, payload: dict, merge: bool = False) -> None:
        if merge and self.id in self._store:
            merged = dict(self._store[self.id])
            merged.update(payload)
            self._store[self.id] = merged
            return
        self._store[self.id] = dict(payload)


class _FakeCollection:
    def __init__(self, store: dict[str, dict]):
        self._store = store
        self._limit = None

    def document(self, doc_id: str | None = None):
        next_id = doc_id or f"help-{len(self._store) + 1}"
        return _FakeDocRef(self._store, next_id)

    def order_by(self, *args, **kwargs):
        return self

    def limit(self, count: int):
        self._limit = count
        return self

    def stream(self):
        items = sorted(self._store.items(), key=lambda item: item[1].get("created_utc") or "", reverse=True)
        if self._limit is not None:
            items = items[: self._limit]
        return [_FakeDocSnapshot(doc_id, payload) for doc_id, payload in items]


class _FakeFirestore:
    def __init__(self):
        self._support: dict[str, dict] = {}

    def collection(self, name: str):
        if name != "student_help_requests":
            raise AssertionError(f"Unexpected collection {name}")
        return _FakeCollection(self._support)


class StudentSupportRouterTests(unittest.TestCase):
    def _request(self):
        return SimpleNamespace(
            state=SimpleNamespace(request_id="req-1"),
            headers={"User-Agent": "unittest"},
            client=SimpleNamespace(host="127.0.0.1"),
        )

    def test_create_help_request_stores_context(self) -> None:
        fake_db = _FakeFirestore()
        payload = HelpRequestCreateIn(
            category="stuck",
            subject="Need help with F2 vectors",
            message="I am stuck comparing scalar and vector answers in the quick check.",
            module_id="f2",
            module_title="Motion, Forces and Energy",
            lesson_id="F2_L1",
            lesson_title="Scalars and vectors",
            page_path="/student/module/F2",
        )

        with patch("app.routers.student_support.get_firestore_client", return_value=fake_db), patch(
            "app.routers.student_support.write_audit_log"
        ):
            response = student_support.create_help_request(
                request=self._request(),
                user={"uid": "student-1", "email": "student@example.com", "role": "student"},
                payload=payload,
            )

        self.assertTrue(response["ok"])
        self.assertEqual(response["request"]["module_id"], "F2")
        self.assertEqual(response["request"]["lesson_id"], "F2_L1")
        self.assertEqual(response["request"]["student_email"], "student@example.com")

    def test_list_help_requests_filters_by_module_and_status(self) -> None:
        fake_db = _FakeFirestore()
        fake_db._support = {
            "help-1": {
                "student_uid": "student-1",
                "student_email": "one@example.com",
                "student_role": "student",
                "category": "content",
                "subject": "F2 question",
                "message": "Please help with vectors.",
                "module_id": "F2",
                "lesson_id": "F2_L1",
                "status": "open",
                "created_utc": "2026-03-27T10:00:00+00:00",
                "updated_utc": "2026-03-27T10:00:00+00:00",
            },
            "help-2": {
                "student_uid": "student-2",
                "student_email": "two@example.com",
                "student_role": "student",
                "category": "technical",
                "subject": "F3 issue",
                "message": "Simulation would not load.",
                "module_id": "F3",
                "lesson_id": "F3_L2",
                "status": "resolved",
                "created_utc": "2026-03-27T11:00:00+00:00",
                "updated_utc": "2026-03-27T11:00:00+00:00",
            },
        }

        with patch("app.routers.student_support.get_firestore_client", return_value=fake_db), patch(
            "app.routers.student_support.write_audit_log"
        ):
            response = student_support.list_help_requests(
                request=self._request(),
                user={"uid": "teacher-1", "email": "teacher@example.com", "role": "instructor"},
                limit=10,
                status="open",
                module_id="f2",
            )

        self.assertEqual(len(response["inquiries"]), 1)
        self.assertEqual(response["inquiries"][0]["module_id"], "F2")
        self.assertEqual(response["inquiries"][0]["status"], "open")

    def test_resolve_help_request_marks_item_resolved(self) -> None:
        fake_db = _FakeFirestore()
        fake_db._support = {
            "help-1": {
                "student_uid": "student-1",
                "student_email": "one@example.com",
                "student_role": "student",
                "category": "stuck",
                "subject": "F1 question",
                "message": "Please help with SI units.",
                "module_id": "F1",
                "lesson_id": "F1_L1",
                "status": "open",
                "created_utc": "2026-04-03T21:44:12+00:00",
                "updated_utc": "2026-04-03T21:44:12+00:00",
            }
        }

        with patch("app.routers.student_support.get_firestore_client", return_value=fake_db), patch(
            "app.routers.student_support.write_audit_log"
        ):
            response = student_support.resolve_help_request(
                request_id="help-1",
                request=self._request(),
                user={"uid": "teacher-1", "email": "teacher@example.com", "role": "instructor"},
            )

        self.assertTrue(response["ok"])
        self.assertEqual(response["request"]["status"], "resolved")
        self.assertEqual(fake_db._support["help-1"]["status"], "resolved")
        self.assertEqual(fake_db._support["help-1"]["resolved_by_email"], "teacher@example.com")


if __name__ == "__main__":
    unittest.main()
