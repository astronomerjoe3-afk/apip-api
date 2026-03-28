from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.services import institution_service


class _FakeDocSnapshot:
    def __init__(self, doc_id: str, payload: dict | None):
        self.id = doc_id
        self._payload = payload
        self.exists = payload is not None

    def to_dict(self) -> dict:
        return dict(self._payload or {})


class _FakeDocRef:
    def __init__(self, store: dict[str, dict], doc_id: str):
        self._store = store
        self.id = doc_id

    def set(self, payload: dict, merge: bool = False) -> None:
        current = dict(self._store.get(self.id) or {})
        if merge:
            current.update(payload)
            self._store[self.id] = current
        else:
            self._store[self.id] = dict(payload)

    def get(self) -> _FakeDocSnapshot:
        return _FakeDocSnapshot(self.id, self._store.get(self.id))


class _FakeCollection:
    def __init__(self, store: dict[str, dict]):
        self._store = store

    def document(self, doc_id: str):
        return _FakeDocRef(self._store, doc_id)

    def stream(self):
        return [_FakeDocSnapshot(doc_id, payload) for doc_id, payload in self._store.items()]


class _FakeFirestore:
    def __init__(self, collections: dict[str, dict[str, dict]]):
        self._collections = collections

    def collection(self, name: str):
        store = self._collections.setdefault(name, {})
        return _FakeCollection(store)


class InstitutionServiceTests(unittest.TestCase):
    def _fake_db(self) -> _FakeFirestore:
        return _FakeFirestore(
            {
                "institutions": {
                    "inst_1": {
                        "name": "Alpha School",
                        "slug": "alpha-school",
                        "committed_student_seats": 120,
                        "public_community_enabled": False,
                        "status": "active",
                    }
                },
                "institution_memberships": {
                    "inst_1:teacher-1": {
                        "institution_id": "inst_1",
                        "uid": "teacher-1",
                        "role": "teacher",
                        "email": "teacher1@example.com",
                        "display_name": "Teacher One",
                        "status": "active",
                    },
                    "inst_1:teacher-2": {
                        "institution_id": "inst_1",
                        "uid": "teacher-2",
                        "role": "teacher",
                        "email": "teacher2@example.com",
                        "display_name": "Teacher Two",
                        "status": "active",
                    },
                    "inst_1:student-1": {
                        "institution_id": "inst_1",
                        "uid": "student-1",
                        "role": "student",
                        "email": "student1@example.com",
                        "display_name": "Student One",
                        "status": "active",
                    },
                },
                "institution_classes": {
                    "class_1": {
                        "institution_id": "inst_1",
                        "name": "Physics 10A",
                        "teacher_uids": ["teacher-1"],
                        "student_uids": ["student-1"],
                        "join_code": "JOIN10A",
                        "status": "active",
                    },
                    "class_2": {
                        "institution_id": "inst_1",
                        "name": "Physics 10B",
                        "teacher_uids": ["teacher-2"],
                        "student_uids": [],
                        "join_code": "JOIN10B",
                        "status": "active",
                    },
                },
                "institution_assignments": {
                    "assign_1": {
                        "institution_id": "inst_1",
                        "class_id": "class_1",
                        "title": "Momentum check",
                        "assignment_type": "platform_resource",
                        "instructions": "Complete M3 mission tasks.",
                        "resource_module_ids": ["M3"],
                        "status": "published",
                    },
                    "assign_2": {
                        "institution_id": "inst_1",
                        "class_id": "class_2",
                        "title": "Force lab",
                        "assignment_type": "custom",
                        "instructions": "Upload your force diagram.",
                        "status": "published",
                    },
                },
                "institution_submissions": {
                    "assign_1:student-1": {
                        "institution_id": "inst_1",
                        "class_id": "class_1",
                        "assignment_id": "assign_1",
                        "student_uid": "student-1",
                        "student_email": "student1@example.com",
                        "status": "submitted",
                        "text_response": "Done",
                        "submitted_utc": "2026-03-28T09:00:00+00:00",
                    }
                },
                "institution_discussions": {
                    "disc_1": {
                        "institution_id": "inst_1",
                        "class_id": "class_1",
                        "scope": "class",
                        "title": "Quiz questions",
                        "body": "Ask follow-up questions here.",
                        "created_by_uid": "teacher-1",
                        "created_by_role": "teacher",
                        "created_utc": "2026-03-28T08:00:00+00:00",
                    },
                    "disc_public": {
                        "scope": "public_topic",
                        "title": "Energy conservation",
                        "body": "Share one example from daily life.",
                        "module_id": "M3",
                        "created_by_uid": "student-2",
                        "created_by_role": "student",
                        "created_utc": "2026-03-28T07:00:00+00:00",
                    },
                },
            }
        )

    def test_teacher_workspace_is_scoped_to_own_classes(self) -> None:
        fake_db = self._fake_db()
        with patch("app.services.institution_service.get_firestore_client", return_value=fake_db):
            workspace = institution_service.build_institutions_workspace(
                {"uid": "teacher-1", "email": "teacher1@example.com", "role": "teacher"}
            )

        self.assertTrue(workspace["ok"])
        self.assertEqual(workspace["viewer"]["role"], "teacher")
        self.assertEqual(len(workspace["institutions"]), 1)
        classes = workspace["institutions"][0]["classes"]
        self.assertEqual([row["id"] for row in classes], ["class_1"])
        self.assertEqual(classes[0]["assignments"][0]["id"], "assign_1")
        self.assertEqual(len(workspace["public_topic_discussions"]), 1)

    def test_teacher_can_add_students_but_not_teachers(self) -> None:
        fake_db = self._fake_db()
        with patch("app.services.institution_service.get_firestore_client", return_value=fake_db):
            created = institution_service.create_membership(
                {"uid": "teacher-1", "email": "teacher1@example.com", "role": "teacher"},
                "inst_1",
                {
                    "uid": "student-2",
                    "role": "student",
                    "email": "student2@example.com",
                    "display_name": "Student Two",
                },
            )

            self.assertEqual(created["role"], "student")

            with self.assertRaises(HTTPException) as error:
                institution_service.create_membership(
                    {"uid": "teacher-1", "email": "teacher1@example.com", "role": "teacher"},
                    "inst_1",
                    {
                        "uid": "teacher-3",
                        "role": "teacher",
                        "email": "teacher3@example.com",
                    },
                )

        self.assertEqual(error.exception.status_code, 403)

    def test_student_submission_and_teacher_grading_flow(self) -> None:
        fake_db = self._fake_db()
        with patch("app.services.institution_service.get_firestore_client", return_value=fake_db):
            submission = institution_service.upsert_submission(
                {"uid": "student-1", "email": "student1@example.com", "role": "student"},
                "assign_1",
                {
                    "text_response": "My momentum explanation",
                    "attachment_names": ["momentum-notes.pdf"],
                },
            )
            graded = institution_service.grade_submission(
                {"uid": "teacher-1", "email": "teacher1@example.com", "role": "teacher"},
                submission["id"],
                {
                    "score": 88,
                    "feedback": "Good job. Explain impulse more clearly next time.",
                    "status": "graded",
                },
            )

        self.assertEqual(submission["status"], "submitted")
        self.assertEqual(graded["status"], "graded")
        self.assertEqual(graded["score"], 88)
        self.assertIn("Explain impulse", graded["feedback"])


if __name__ == "__main__":
    unittest.main()
