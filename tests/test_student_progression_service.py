from __future__ import annotations

import unittest
from unittest.mock import patch

from app.services.student_progression_service import get_student_module_progress


def _lesson() -> dict:
    return {
        "id": "M2_L1",
        "lesson_id": "M2_L1",
        "module_id": "M2",
        "title": "Resultant Forces and Cruise State",
        "sequence": 1,
        "phases": {
            "diagnostic": {"items": [{"id": "D1"}]},
            "analogical_grounding": {"analogy_text": "Master Arrow", "micro_prompts": [{"prompt": "P1"}]},
            "simulation_inquiry": {"lab_id": "m2_resultant_force_lab"},
            "concept_reconstruction": {
                "prompts": ["Explain the idea."],
                "capsules": [{"prompt": "Remember this", "checks": [{"id": "C1"}]}],
            },
            "transfer": {"items": [{"id": "T1"}, {"id": "T2"}]},
        },
        "authoring_contract": {
            "misconception_focus": [
                "motion_implies_force_confusion",
                "balanced_force_rest_confusion",
            ]
        },
    }


def _event(event_type: str, *, source: str = "", score: float | None = None) -> dict:
    details = {"lesson_id": "M2_L1"}
    if source:
        details["source"] = source
    payload = {
        "event_type": event_type,
        "details": details,
        "utc": "2026-03-17T00:00:00+00:00",
    }
    if score is not None:
        payload["score"] = score
    return payload


class StudentProgressionServiceTests(unittest.TestCase):
    def _progress_for_events(self, events: list[dict]) -> dict:
        with patch("app.services.student_progression_service.get_module_lessons", return_value=[_lesson()]), patch(
            "app.services.student_progression_service.get_progress_events", return_value=events
        ), patch("app.services.student_progression_service.get_module_progress", return_value={}):
            payload = get_student_module_progress(uid="student-1", module_id="M2")
        return payload["lessons"][0]

    def test_teaching_event_advances_instructional_status_without_breaking_legacy_status(self) -> None:
        row = self._progress_for_events(
            [
                _event("diagnostic", score=0.5),
                _event("reflection", source="student_runner_scaffolded_teaching_viewed", score=1.0),
            ]
        )
        self.assertEqual(row["status"], "teaching_completed")
        self.assertEqual(row["instructional_status"], "teaching_completed")
        self.assertFalse(row["completed"])

    def test_concept_gate_completion_is_event_based_not_score_based(self) -> None:
        row = self._progress_for_events(
            [
                _event("diagnostic", score=0.5),
                _event("reflection", source="student_runner_scaffolded_teaching_viewed", score=1.0),
                _event("reflection", source="student_runner_concept_gate", score=0.0),
            ]
        )
        self.assertEqual(row["status"], "concept_gate_completed")
        self.assertEqual(row["instructional_status"], "concept_gate_completed")
        self.assertTrue(row["concept_gate_completed"])

    def test_simulation_only_changes_legacy_status(self) -> None:
        row = self._progress_for_events(
            [
                _event("diagnostic", score=0.5),
                _event("reflection", source="student_runner_scaffolded_teaching_viewed", score=1.0),
                _event("reflection", source="student_runner_concept_gate", score=1.0),
                _event("simulation", score=1.0),
            ]
        )
        self.assertEqual(row["status"], "simulation_completed")
        self.assertEqual(row["instructional_status"], "concept_gate_completed")
        self.assertTrue(row["simulation_completed"])
        self.assertTrue(row["lab_used"])

    def test_failed_mastery_keeps_instructional_completion_false(self) -> None:
        row = self._progress_for_events(
            [
                _event("diagnostic", score=0.5),
                _event("reflection", source="student_runner_scaffolded_teaching_viewed", score=1.0),
                _event("reflection", source="student_runner_concept_gate", score=1.0),
                _event("simulation", score=1.0),
                _event("transfer", score=0.6),
            ]
        )
        self.assertEqual(row["status"], "attempted_not_completed")
        self.assertEqual(row["instructional_status"], "attempted_not_completed")
        self.assertTrue(row["can_advance"])
        self.assertFalse(row["instructional_can_advance"])

    def test_passing_mastery_completes_both_models(self) -> None:
        row = self._progress_for_events(
            [
                _event("diagnostic", score=0.5),
                _event("reflection", source="student_runner_scaffolded_teaching_viewed", score=1.0),
                _event("reflection", source="student_runner_concept_gate", score=1.0),
                _event("transfer", score=0.9),
            ]
        )
        self.assertEqual(row["status"], "completed")
        self.assertEqual(row["instructional_status"], "completed")
        self.assertTrue(row["completed"])
        self.assertTrue(row["instructional_can_advance"])

