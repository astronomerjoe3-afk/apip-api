from __future__ import annotations

import unittest
from unittest.mock import patch

from app.services.catalog_service import fetch_module_lesson
from app.services.student_runner_service import _load_lesson


class LessonLookupResolutionTests(unittest.TestCase):
    def test_catalog_service_prefers_module_scoped_lookup_before_doc_id_lookup(self) -> None:
        lesson_row = {"lesson_id": "M7_L1", "module_id": "M7", "title": "Traveling pattern"}

        with patch("app.services.catalog_service.get_lesson_by_fields", return_value=lesson_row) as by_fields, patch(
            "app.services.catalog_service.get_lesson_by_doc_id",
            side_effect=AssertionError("doc-id fallback should not run when module-scoped lookup succeeds"),
        ), patch(
            "app.services.catalog_service.to_student_lesson_view",
            side_effect=lambda lesson: {"lesson_id": lesson["lesson_id"], "title": lesson["title"]},
        ):
            lesson = fetch_module_lesson("M7", "M7_L1")

        self.assertEqual(lesson["lesson_id"], "M7_L1")
        by_fields.assert_called_once_with("M7", "M7_L1")

    def test_catalog_service_accepts_camel_case_module_id_on_doc_id_fallback(self) -> None:
        lesson_row = {"lesson_id": "M7_L1", "moduleId": "M7", "title": "Traveling pattern"}

        with patch("app.services.catalog_service.get_lesson_by_fields", return_value=None), patch(
            "app.services.catalog_service.get_lesson_by_doc_id", return_value=lesson_row
        ), patch(
            "app.services.catalog_service.to_student_lesson_view",
            side_effect=lambda lesson: {"lesson_id": lesson["lesson_id"], "title": lesson["title"]},
        ):
            lesson = fetch_module_lesson("M7", "M7_L1")

        self.assertEqual(lesson["lesson_id"], "M7_L1")

    def test_student_runner_prefers_module_scoped_lookup_before_doc_id_fallback(self) -> None:
        lesson_row = {"lesson_id": "M7_L1", "module_id": "M7", "title": "Traveling pattern"}

        with patch("app.services.student_runner_service.get_lesson_by_fields", return_value=lesson_row) as by_fields, patch(
            "app.services.student_runner_service.get_lesson_by_doc_id",
            side_effect=AssertionError("doc-id fallback should not run when module-scoped lookup succeeds"),
        ):
            lesson = _load_lesson("M7", "M7_L1")

        self.assertEqual(lesson, lesson_row)
        by_fields.assert_called_once_with("M7", "M7_L1")

    def test_student_runner_accepts_camel_case_module_id_on_doc_id_fallback(self) -> None:
        lesson_row = {"lesson_id": "M7_L1", "moduleId": "M7", "title": "Traveling pattern"}

        with patch("app.services.student_runner_service.get_lesson_by_fields", return_value=None), patch(
            "app.services.student_runner_service.get_lesson_by_doc_id", return_value=lesson_row
        ):
            lesson = _load_lesson("M7", "M7_L1")

        self.assertEqual(lesson, lesson_row)


if __name__ == "__main__":
    unittest.main()
