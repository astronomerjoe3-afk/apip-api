from __future__ import annotations

import unittest

from scripts.seed_m6_module import M6_LESSONS
from scripts.seed_m7_module import M7_LESSONS
from scripts.seed_m8_module import M8_LESSONS
from scripts.seed_m9_module import M9_LESSONS
from scripts.seed_m10_module import M10_LESSONS
from scripts.seed_m11_module import M11_LESSONS
from scripts.seed_m12_module import M12_LESSONS
from scripts.seed_m13_module import M13_LESSONS
from scripts.seed_m14_module import M14_LESSONS, M14_MODULE_DOC
from scripts.seed_m15_module import M15_LESSONS
from scripts.seed_a1_module import A1_LESSONS
from scripts.seed_a2_module import A2_LESSONS
from scripts.seed_a3_module import A3_LESSONS
from scripts.seed_a5_module import A5_LESSONS


class LessonAssessmentScopeContractTests(unittest.TestCase):
    def _assert_assessed_skills_declared(self, lesson_pairs) -> None:
        for _, lesson in lesson_pairs:
            contract = lesson.get("authoring_contract") or {}
            declared_skills = {
                str(skill)
                for skill in contract.get("mastery_skills") or []
                if str(skill).strip()
            }
            if not declared_skills:
                continue

            capsules = lesson.get("phases", {}).get("concept_reconstruction", {}).get("capsules", [])
            concept_items = []
            for capsule in capsules:
                concept_items.extend(capsule.get("checks") or [])
            mastery_items = lesson.get("phases", {}).get("transfer", {}).get("items") or []

            for phase_name, items in (("concept", concept_items), ("mastery", mastery_items)):
                for item in items:
                    for skill in item.get("skill_tags") or []:
                        self.assertIn(
                            skill,
                            declared_skills,
                            f"{lesson.get('lesson_id')}: {phase_name} assessment skill '{skill}' must be declared in mastery_skills before it is assessed.",
                        )

    def test_recent_generated_modules_only_assess_declared_lesson_skills(self) -> None:
        for lesson_pairs in (
            M6_LESSONS,
            M7_LESSONS,
            M8_LESSONS,
            M9_LESSONS,
            M10_LESSONS,
            M11_LESSONS,
            M12_LESSONS,
            M13_LESSONS,
            M14_LESSONS,
            M15_LESSONS,
            A1_LESSONS,
            A2_LESSONS,
            A3_LESSONS,
            A5_LESSONS,
        ):
            self._assert_assessed_skills_declared(lesson_pairs)

    def test_m14_l1_teaches_dwarf_planet_rule_before_using_it(self) -> None:
        self.assertEqual(M14_MODULE_DOC["id"], "M14")

        lesson = next(payload for lesson_id, payload in M14_LESSONS if lesson_id == "M14_L1")
        contract = lesson["authoring_contract"]
        core_text = " ".join(contract.get("core_concepts") or []).lower()
        scaffold = contract.get("scaffold_support") or {}
        scaffold_text = " ".join(
            [
                str(scaffold.get("core_idea") or ""),
                str(scaffold.get("reasoning") or ""),
                *[
                    " ".join(
                        [
                            str(section.get("heading") or ""),
                            str(section.get("body") or ""),
                            str(section.get("check_for_understanding") or ""),
                        ]
                    )
                    for section in scaffold.get("extra_sections") or []
                ],
            ]
        ).lower()
        worked_text = " ".join(example.get("prompt") or "" for example in contract.get("worked_examples") or []).lower()

        self.assertIn("neighborhood", core_text)
        self.assertIn("dwarf planet", core_text)
        self.assertIn("neighborhood", scaffold_text)
        self.assertIn("neighborhood", worked_text)
        self.assertIn("classify_dwarf_planet", contract["mastery_skills"])
        self.assertIn("main_host_reasoning", contract["mastery_skills"])
        self.assertIn("category_counting", contract["mastery_skills"])


if __name__ == "__main__":
    unittest.main()
