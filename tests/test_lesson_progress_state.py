from __future__ import annotations

import unittest

from app.services.lesson_progress_state import apply_progress_event_to_snapshot


class LessonProgressStateTests(unittest.TestCase):
    def test_scaffold_view_event_updates_teaching_snapshot(self) -> None:
        snapshot = apply_progress_event_to_snapshot(
            {},
            lesson_id="F1_L1",
            event_type_value="reflection",
            score=1.0,
            details={
                "lesson_id": "F1_L1",
                "source": "student_runner_scaffolded_teaching_viewed",
            },
            utc="2026-03-27T12:00:00+00:00",
        )

        self.assertEqual(snapshot["lesson_id"], "F1_L1")
        self.assertEqual(snapshot["teaching_event_count"], 1)
        self.assertEqual(snapshot["teaching_view_count"], 1)
        self.assertEqual(snapshot["concept_gate_count"], 0)

    def test_concept_gate_event_tracks_gate_completion_signal(self) -> None:
        snapshot = apply_progress_event_to_snapshot(
            {},
            lesson_id="F1_L1",
            event_type_value="reflection",
            score=1.0,
            details={
                "lesson_id": "F1_L1",
                "source": "student_runner_concept_gate",
            },
            utc="2026-03-27T12:05:00+00:00",
        )

        self.assertEqual(snapshot["concept_gate_count"], 1)
        self.assertEqual(snapshot["concept_gate_best_score"], 1.0)

