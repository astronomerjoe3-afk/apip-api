from __future__ import annotations

from pathlib import Path
import unittest

from app.services.content_normalizer import to_student_lesson_view
from scripts.revised_advanced_curriculum_modules import (
    A6_LESSONS,
    A7_LESSONS,
    A8_LESSONS,
    A9_LESSONS,
    A10_LESSONS,
    A11_LESSONS,
)
from scripts.revised_core_curriculum_modules import F5_LESSONS
from scripts.seed_a1_module import A1_LESSONS
from scripts.seed_a2_module import A2_LESSONS
from scripts.seed_a3_module import A3_LESSONS
from scripts.seed_a4_module import A4_LESSONS
from scripts.seed_a5_module import A5_LESSONS
from scripts.seed_f1_module import F1_LESSONS
from scripts.seed_f2_module import F2_LESSONS
from scripts.seed_f3_module import F3_LESSONS
from scripts.seed_f4_module import F4_LESSONS
from scripts.seed_m1_module import M1_LESSONS
from scripts.seed_m2_module import M2_LESSONS
from scripts.seed_m3_module import M3_LESSONS
from scripts.seed_m4_module import M4_LESSONS
from scripts.seed_m5_module import M5_LESSONS
from scripts.seed_m6_module import M6_LESSONS
from scripts.seed_m7_module import M7_LESSONS
from scripts.seed_m8_module import M8_LESSONS
from scripts.seed_m9_module import M9_LESSONS
from scripts.seed_m10_module import M10_LESSONS
from scripts.seed_m11_module import M11_LESSONS
from scripts.seed_m12_module import M12_LESSONS
from scripts.seed_m13_module import M13_LESSONS
from scripts.seed_m14_module import M14_LESSONS


MODULE_LESSONS = {
    "F1": F1_LESSONS,
    "F2": F2_LESSONS,
    "F3": F3_LESSONS,
    "F4": F4_LESSONS,
    "F5": F5_LESSONS,
    "M1": M1_LESSONS,
    "M2": M2_LESSONS,
    "M3": M3_LESSONS,
    "M4": M4_LESSONS,
    "M5": M5_LESSONS,
    "M6": M6_LESSONS,
    "M7": M7_LESSONS,
    "M8": M8_LESSONS,
    "M9": M9_LESSONS,
    "M10": M10_LESSONS,
    "M11": M11_LESSONS,
    "M12": M12_LESSONS,
    "M13": M13_LESSONS,
    "M14": M14_LESSONS,
    "A1": A1_LESSONS,
    "A2": A2_LESSONS,
    "A3": A3_LESSONS,
    "A4": A4_LESSONS,
    "A5": A5_LESSONS,
    "A6": A6_LESSONS,
    "A7": A7_LESSONS,
    "A8": A8_LESSONS,
    "A9": A9_LESSONS,
    "A10": A10_LESSONS,
    "A11": A11_LESSONS,
}


class FormulaBridgeContractTests(unittest.TestCase):
    def test_student_view_keeps_formula_and_analogy_bridge_fields(self) -> None:
        lesson = {
            "id": "M3_L1",
            "lesson_id": "M3_L1",
            "module_id": "M3",
            "title": "Work Done and Energy Transfer",
            "sequence": 1,
            "phases": {
                "analogical_grounding": {"analogy_text": "Energy Ledger"},
                "simulation_inquiry": {},
                "concept_reconstruction": {"capsules": []},
                "diagnostic": {"items": []},
                "transfer": {"items": []},
            },
            "authoring_contract": {
                "technical_words": [
                    {
                        "term": "Work done",
                        "meaning": "Energy transferred when a force acts through a distance.",
                    }
                ],
                "formulas": [
                    {
                        "equation": "W = Fd",
                        "meaning": "Work done equals force multiplied by displacement in the force direction.",
                        "units": ["J", "N", "m"],
                        "conditions": "Use when the force and displacement stay aligned in the simple model.",
                    }
                ],
                "analogy_map": {
                    "comparison": "The energy ledger records a payout only when the crate actually moves through the hand-off gate.",
                    "mapping": [
                        "Ledger payout stands for energy transfer by work done.",
                        "Gate travel distance stands for displacement in the force direction.",
                    ],
                    "limit": "The ledger is only a bridge for the work story, not a literal machine inside the box.",
                    "prediction_prompt": "If the worker pushes but the crate does not move, what should happen to the ledger?",
                },
            },
        }

        payload = to_student_lesson_view(lesson)

        self.assertEqual(payload["authoring_contract"]["formulas"][0]["equation"], "W = Fd")
        self.assertEqual(
            payload["authoring_contract"]["analogy_map"]["comparison"],
            "The energy ledger records a payout only when the crate actually moves through the hand-off gate.",
        )

    def test_every_foundation_core_and_advanced_lesson_has_formula_bridge_inputs(self) -> None:
        for module_id, lessons in MODULE_LESSONS.items():
            for lesson_id, lesson in lessons:
                with self.subTest(module_id=module_id, lesson_id=lesson_id):
                    contract = lesson.get("authoring_contract") or {}
                    formulas = list(contract.get("formulas") or [])
                    analogy_map = dict(contract.get("analogy_map") or {})
                    mapping = [str(item).strip() for item in analogy_map.get("mapping") or [] if str(item).strip()]

                    self.assertGreaterEqual(len(formulas), 1)
                    self.assertTrue(str(analogy_map.get("comparison") or "").strip())
                    self.assertGreaterEqual(len(mapping), 2)

                    for formula in formulas:
                        standard_formula = (
                            formula.get("equation")
                            or formula.get("formula")
                            or formula.get("relation")
                            or formula.get("expression")
                            or ""
                        )
                        self.assertTrue(str(standard_formula).strip())
                        self.assertTrue(str(formula.get("meaning") or "").strip())
                        self.assertTrue(str(formula.get("conditions") or "").strip())

    def test_web_runner_places_formula_bridge_directly_before_worked_examples(self) -> None:
        web_root = Path(__file__).resolve().parents[2] / "apip-web"
        lesson_runner_api = web_root / "lib" / "lessonRunnerApi.ts"
        content = lesson_runner_api.read_text(encoding="utf-8")

        self.assertIn('heading: "Standard formulas and analogy bridge"', content)
        self.assertIn(
            "...(formulaBridge ? [formulaBridge] : []),\n    ...scaffoldWorkedExampleSections(workedExample),",
            content,
        )
        self.assertIn(
            'const workedExampleIndex = nextSections.findIndex((section) => Object.keys(asRecord(asRecord(section).worked_example)).length > 0);',
            content,
        )
        self.assertIn("nextSections.splice(insertIndex, 0, formulaSection);", content)


if __name__ == "__main__":
    unittest.main()
