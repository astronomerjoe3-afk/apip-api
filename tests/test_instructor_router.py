from __future__ import annotations

import unittest

from app.routers import instructor


class InstructorRouterSnapshotTests(unittest.TestCase):
    def test_build_activity_snapshots_uses_lesson_progress_rows_instead_of_event_queries(self) -> None:
        lesson_rows = [
            {
                "lesson_id": "F1_L1",
                "diagnostic_latest_score": 0.35,
                "diagnostic_last_utc": "2026-04-04T08:00:00+00:00",
                "latest_score": 0.72,
                "last_mastery_check_utc": "2026-04-04T10:00:00+00:00",
            },
            {
                "lesson_id": "F1_L2",
                "diagnostic_latest_score": 0.64,
                "diagnostic_last_utc": "2026-04-04T09:30:00+00:00",
                "latest_score": 0.81,
                "last_mastery_check_utc": "2026-04-04T11:15:00+00:00",
            },
            {
                "lesson_id": "F1_L3",
                "diagnostic_latest_score": None,
                "diagnostic_last_utc": None,
                "latest_score": 0.55,
                "last_mastery_check_utc": "2026-04-04T07:00:00+00:00",
            },
        ]

        last_diagnostic, last_transfer, per_lesson = instructor._build_activity_snapshots(lesson_rows)

        self.assertEqual(last_diagnostic, {"score": 0.64, "utc": "2026-04-04T09:30:00+00:00"})
        self.assertEqual(last_transfer, {"score": 0.81, "utc": "2026-04-04T11:15:00+00:00"})
        self.assertEqual(
            per_lesson["F1_L1"],
            {
                "diagnostic": {"score": 0.35, "utc": "2026-04-04T08:00:00+00:00"},
                "transfer": {"score": 0.72, "utc": "2026-04-04T10:00:00+00:00"},
            },
        )
        self.assertEqual(
            per_lesson["F1_L2"],
            {
                "diagnostic": {"score": 0.64, "utc": "2026-04-04T09:30:00+00:00"},
                "transfer": {"score": 0.81, "utc": "2026-04-04T11:15:00+00:00"},
            },
        )
        self.assertEqual(
            per_lesson["F1_L3"],
            {"transfer": {"score": 0.55, "utc": "2026-04-04T07:00:00+00:00"}},
        )


if __name__ == "__main__":
    unittest.main()
