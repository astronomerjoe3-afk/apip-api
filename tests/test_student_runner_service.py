from __future__ import annotations

import unittest
from unittest.mock import patch

from app.services.student_runner_service import build_student_runner_contract


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


def _lesson_with_authored_reflection_only() -> dict:
    return {
        "id": "F1_L1",
        "lesson_id": "F1_L1",
        "module_id": "F1",
        "title": "SI Units, Prefixes, and Complete Measurements",
        "sequence": 1,
        "phases": {
            "diagnostic": {"items": [{"id": "D1"}]},
            "analogical_grounding": {"analogy_text": "Shared currency", "micro_prompts": [{"prompt": "P1"}]},
            "simulation_inquiry": {"lab_id": "f1_metric_prefix_lab"},
            "concept_reconstruction": {
                "prompts": [],
                "capsules": [{"checks": [{"id": "C1"}]}],
            },
            "transfer": {"items": [{"id": "T1"}, {"id": "T2"}]},
        },
        "authoring_contract": {
            "reflection_prompts": [
                "Explain why the same physical quantity can be written with different unit labels."
            ],
        },
    }


def _progress(*, status: str, instructional_status: str, lab_used: bool = False, best_score: float = 0.0, latest_score: float | None = None, mastery_check_count: int = 0, can_advance: bool = False) -> dict:
    return {
        "module": {
            "module_id": "M2",
            "module_mastery": best_score,
            "lessons_completed_count": 0,
            "total_lessons": 1,
        },
        "lesson": {
            "lesson_id": "M2_L1",
            "title": "Resultant Forces and Cruise State",
            "sequence": 1,
            "best_score": best_score,
            "latest_score": latest_score,
            "attempt_count": mastery_check_count,
            "completed": best_score >= 0.8,
            "can_advance": can_advance,
            "instructional_can_advance": best_score >= 0.8,
            "lab_available": not lab_used,
            "lab_used": lab_used,
            "status": status,
            "instructional_status": instructional_status,
            "diagnostic_count": 1,
            "diagnostic_latest_score": 0.9,
            "diagnostic_asked_count": 3,
            "teaching_view_count": 1,
            "teaching_reconstruction_count": 0,
            "teaching_completed": True,
            "concept_gate_count": 1,
            "concept_gate_completed": instructional_status
            in {"concept_gate_completed", "attempted_not_completed", "completed"},
            "simulation_completed": lab_used,
            "reflection_completed": status in {"reflection_completed", "attempted_not_completed", "completed"},
            "mastery_check_count": mastery_check_count,
        },
    }


class StudentRunnerServiceTests(unittest.TestCase):
    def _runner(self, progress_payload: dict) -> dict:
        with patch("app.services.student_runner_service._load_lesson", return_value=_lesson()), patch(
            "app.services.student_runner_service.get_student_lesson_progress", return_value=progress_payload
        ):
            payload = build_student_runner_contract(uid="student-1", module_id="M2", lesson_id="M2_L1")
        return payload["lesson"]

    def _runner_for_lesson(self, lesson_payload: dict, progress_payload: dict, *, module_id: str, lesson_id: str) -> dict:
        with patch("app.services.student_runner_service._load_lesson", return_value=lesson_payload), patch(
            "app.services.student_runner_service.get_student_lesson_progress", return_value=progress_payload
        ):
            payload = build_student_runner_contract(uid="student-1", module_id=module_id, lesson_id=lesson_id)
        return payload["lesson"]

    def test_merged_runner_keeps_legacy_reflection_stage_and_new_instructional_stage(self) -> None:
        lesson = self._runner(
            _progress(
                status="simulation_completed",
                instructional_status="concept_gate_completed",
                lab_used=True,
            )
        )
        self.assertEqual(lesson["active_stage"], "reflection")
        self.assertEqual(lesson["instructional_active_stage"], "mastery_check")

    def test_instructional_stage_points_to_concept_gate_after_teaching(self) -> None:
        lesson = self._runner(
            _progress(
                status="teaching_completed",
                instructional_status="teaching_completed",
                lab_used=False,
            )
        )
        self.assertEqual(lesson["active_stage"], "concept_gate")
        self.assertEqual(lesson["instructional_active_stage"], "concept_gate")

    def test_mastery_question_count_never_exceeds_real_pool(self) -> None:
        lesson = self._runner(
            _progress(
                status="concept_gate_completed",
                instructional_status="concept_gate_completed",
                lab_used=True,
            )
        )
        self.assertEqual(lesson["mastery_check"]["selected_question_count"], 3)

    def test_failed_mastery_exposes_retest_and_review_metadata(self) -> None:
        lesson = self._runner(
            _progress(
                status="attempted_not_completed",
                instructional_status="attempted_not_completed",
                lab_used=True,
                best_score=0.6,
                latest_score=0.6,
                mastery_check_count=1,
                can_advance=True,
            )
        )
        self.assertTrue(lesson["mastery_check"]["eligible_for_immediate_retest"])
        self.assertTrue(lesson["mastery_check"]["review_required"])
        self.assertEqual(
            lesson["mastery_check"]["weak_concepts"],
            ["motion_implies_force_confusion", "balanced_force_rest_confusion"],
        )
        self.assertEqual(
            lesson["mastery_check"]["recommended_review_refs"],
            [
                "concept_motion_implies_force_confusion",
                "concept_balanced_force_rest_confusion",
            ],
        )

    def test_authored_reflection_prompts_keep_reflection_stage_available(self) -> None:
        lesson = self._runner_for_lesson(
            _lesson_with_authored_reflection_only(),
            _progress(
                status="simulation_completed",
                instructional_status="concept_gate_completed",
                lab_used=True,
            ),
            module_id="F1",
            lesson_id="F1_L1",
        )
        self.assertEqual(lesson["active_stage"], "reflection")
        reflection_stage = next(stage for stage in lesson["stages"] if stage["key"] == "reflection")
        self.assertTrue(reflection_stage["available"])
        self.assertTrue(reflection_stage["active"])
