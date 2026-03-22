import unittest

from scripts.seed_m14_module import M14_LESSONS, M14_MODULE_DOC, M14_SIM_LABS


class M14QualityContractTests(unittest.TestCase):
    def test_m14_bundle_uses_v3_contract_and_generated_assets(self) -> None:
        self.assertEqual(M14_MODULE_DOC["id"], "M14")
        self.assertEqual(M14_MODULE_DOC["title"], "Solar System")
        self.assertEqual(M14_MODULE_DOC["authoring_standard"], "lesson_authoring_spec_v3")
        self.assertEqual(len(M14_LESSONS), 6)
        self.assertEqual(len(M14_SIM_LABS), 6)
        self.assertEqual(
            [lesson_id for lesson_id, _ in M14_LESSONS],
            ["M14_L1", "M14_L2", "M14_L3", "M14_L4", "M14_L5", "M14_L6"],
        )

        simulation_concepts = set()
        focus_prompts = set()
        for _, lesson in M14_LESSONS:
            contract = lesson["authoring_contract"]
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            mastery_items = lesson["phases"]["transfer"]["items"]
            simulation_contract = contract["simulation_contract"]

            self.assertEqual(
                contract["assessment_bank_targets"],
                {
                    "diagnostic_pool_min": 10,
                    "concept_gate_pool_min": 8,
                    "mastery_pool_min": 10,
                    "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
                },
            )
            self.assertGreaterEqual(len(diagnostic_items), 10)
            self.assertGreaterEqual(len(concept_checks), 8)
            self.assertGreaterEqual(len(mastery_items), 10)
            self.assertEqual(len(contract["visual_assets"]), 1)
            self.assertEqual(len(contract["animation_assets"]), 0)
            self.assertEqual(len(lesson["generated_assets"]["diagrams"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["animations"]), 0)
            self.assertIn("generated_lab", lesson["phases"]["simulation_inquiry"])
            self.assertGreaterEqual(len(contract["worked_examples"]), 3)
            self.assertGreaterEqual(len(contract["core_concepts"]), 4)
            self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 4)
            self.assertTrue(contract.get("scaffold_support"))
            self.assertTrue(simulation_contract["asset_id"])
            self.assertTrue(simulation_contract["concept"])
            self.assertTrue(simulation_contract["focus_prompt"])
            self.assertTrue(simulation_contract["baseline_case"])
            self.assertGreaterEqual(len(simulation_contract["controls"]), 2)
            self.assertGreaterEqual(len(simulation_contract["readouts"]), 2)
            self.assertGreaterEqual(len(simulation_contract["comparison_tasks"]), 2)
            simulation_concepts.add(simulation_contract["concept"])
            focus_prompts.add(simulation_contract["focus_prompt"])

            representation_kinds = {item["kind"] for item in contract["representations"]}
            self.assertIn("words", representation_kinds)
            self.assertIn("formula", representation_kinds)
            self.assertTrue(any(kind in {"diagram", "graph", "table", "model", "equation_story"} for kind in representation_kinds))

            skill_tags = set()
            for question in [*diagnostic_items, *concept_checks, *mastery_items]:
                if question["type"] == "short":
                    accepted = question.get("accepted_answers") or []
                    if accepted and not all(str(answer).strip().isdigit() for answer in accepted):
                        self.assertIn("phrase_groups", question.get("acceptance_rules", {}))
                self.assertTrue(question.get("skill_tags"))
                skill_tags.update(question.get("skill_tags") or [])
            self.assertGreaterEqual(len(skill_tags), 4)

        self.assertEqual(len(simulation_concepts), 6)
        self.assertEqual(len(focus_prompts), 6)

    def test_m14_curriculum_scope_stays_on_solar_system(self) -> None:
        mastery_text = " ".join(M14_MODULE_DOC.get("mastery_outcomes") or []).lower()
        description_text = str(M14_MODULE_DOC.get("description") or "").lower()
        self.assertIn("solar system", mastery_text)
        self.assertIn("orbits", mastery_text)
        self.assertIn("day and night", mastery_text)
        self.assertIn("seasons", mastery_text)
        self.assertIn("moon phases", mastery_text)
        self.assertIn("orbital periods", mastery_text)
        self.assertIn("lantern-ring", description_text)
        self.assertNotIn("current", mastery_text)
        self.assertNotIn("pressure", mastery_text)
        self.assertNotIn("photoelectric", mastery_text)

    def test_m14_lessons_balance_conceptual_and_quantitative_reasoning(self) -> None:
        quantitative_tokens = (
            "how many",
            "count",
            "increase",
            "decrease",
            "halve",
            "double",
            "degrees",
            "hours",
            "week",
            "weeks",
            "months",
            "23.4",
            "two weeks",
            "half",
            "quarter",
            "same interval",
            "same pull",
            "same forward motion",
            "compare",
            "wider",
            "narrower",
            "more curved",
            "less curved",
            "tighter",
            "larger",
            "smaller",
            "farther",
            "longer",
            "shorter",
            "stronger",
            "weaker",
            "more laps",
            "fewer laps",
        )
        explanation_tokens = (
            "why",
            "explain",
            "which statement",
            "summarize",
            "strongest",
            "what does",
            "best protects",
        )

        for lesson_id, lesson in M14_LESSONS:
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            mastery_items = lesson["phases"]["transfer"]["items"]
            all_items = [*diagnostic_items, *concept_checks, *mastery_items]
            prompts = [str(item.get("prompt") or "").lower() for item in all_items]

            short_count = sum(1 for item in all_items if item.get("type") == "short")
            quantitative_count = sum(1 for prompt in prompts if any(token in prompt for token in quantitative_tokens) or any(ch.isdigit() for ch in prompt))
            explanation_count = sum(1 for prompt in prompts if any(token in prompt for token in explanation_tokens))
            mastery_short_count = sum(1 for item in mastery_items if item.get("type") == "short")

            self.assertGreaterEqual(short_count, 6, lesson_id)
            self.assertGreaterEqual(quantitative_count, 5, lesson_id)
            self.assertGreaterEqual(explanation_count, 4, lesson_id)
            self.assertGreaterEqual(mastery_short_count, 2, lesson_id)


if __name__ == "__main__":
    unittest.main()
