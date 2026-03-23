from __future__ import annotations

from pathlib import Path
import unittest

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
}


class M1ToM14FormulaBridgeContractTests(unittest.TestCase):
    def test_every_m1_to_m14_lesson_has_authored_formulas_for_the_bridge(self) -> None:
        for module_id, lessons in MODULE_LESSONS.items():
            for lesson_id, lesson in lessons:
                with self.subTest(module_id=module_id, lesson_id=lesson_id):
                    formulas = list((lesson.get("authoring_contract") or {}).get("formulas") or [])
                    self.assertGreaterEqual(len(formulas), 1)
                    for formula in formulas:
                        self.assertTrue(
                            str(
                                formula.get("equation")
                                or formula.get("formula")
                                or formula.get("relation")
                                or formula.get("expression")
                                or ""
                            ).strip()
                        )
                        self.assertTrue(str(formula.get("meaning") or "").strip())

    def test_web_runner_places_formula_bridge_immediately_before_worked_examples(self) -> None:
        web_root = Path(__file__).resolve().parents[2] / "apip-web"
        lesson_runner_api = web_root / "lib" / "lessonRunnerApi.ts"
        content = lesson_runner_api.read_text(encoding="utf-8")

        self.assertIn('heading: "Standard formulas and analogy bridge"', content)
        self.assertIn(
            "...(formulaBridge ? [formulaBridge] : []),\n    ...scaffoldWorkedExampleSections(workedExample),",
            content,
        )


if __name__ == "__main__":
    unittest.main()
