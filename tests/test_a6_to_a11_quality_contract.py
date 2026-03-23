import unittest

from scripts.revised_advanced_curriculum_modules import (
    A6_LESSONS,
    A6_MODULE_DOC,
    A6_SIM_LABS,
    A7_LESSONS,
    A7_MODULE_DOC,
    A7_SIM_LABS,
    A8_LESSONS,
    A8_MODULE_DOC,
    A8_SIM_LABS,
    A9_LESSONS,
    A9_MODULE_DOC,
    A9_SIM_LABS,
    A10_LESSONS,
    A10_MODULE_DOC,
    A10_SIM_LABS,
    A11_LESSONS,
    A11_MODULE_DOC,
    A11_SIM_LABS,
)


MODULES = {
    "A6": (A6_MODULE_DOC, A6_LESSONS, A6_SIM_LABS, "Thermal Physics and Gases"),
    "A7": (A7_MODULE_DOC, A7_LESSONS, A7_SIM_LABS, "DC Circuits and Capacitors"),
    "A8": (A8_MODULE_DOC, A8_LESSONS, A8_SIM_LABS, "Electric and Magnetic Fields"),
    "A9": (A9_MODULE_DOC, A9_LESSONS, A9_SIM_LABS, "Electromagnetic Induction and Power"),
    "A10": (A10_MODULE_DOC, A10_LESSONS, A10_SIM_LABS, "Nuclear and Particle Applications"),
    "A11": (A11_MODULE_DOC, A11_LESSONS, A11_SIM_LABS, "Astrophysics, Gravitation and Cosmology"),
}


class A6ToA11QualityContractTests(unittest.TestCase):
    def test_a6_to_a11_bundles_have_richer_quality_floor(self) -> None:
        for module_id, (module_doc, lessons, sim_labs, expected_title) in MODULES.items():
            with self.subTest(module_id=module_id):
                self.assertEqual(module_doc["id"], module_id)
                self.assertEqual(module_doc["title"], expected_title)
                self.assertEqual(module_doc["authoring_standard"], "lesson_authoring_spec_v3")
                self.assertGreaterEqual(len(module_doc.get("mastery_outcomes") or []), 8)
                self.assertEqual(len(lessons), 6)
                self.assertEqual(len(sim_labs), 6)

                simulation_concepts = set()
                focus_prompts = set()
                for (_, lesson), (_, sim_lab) in zip(lessons, sim_labs):
                    contract = lesson["authoring_contract"]
                    diagnostic_items = lesson["phases"]["diagnostic"]["items"]
                    concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
                    mastery_items = lesson["phases"]["transfer"]["items"]
                    simulation_contract = contract["simulation_contract"]

                    self.assertEqual(
                        contract["assessment_bank_targets"],
                        {
                            "diagnostic_pool_min": 14,
                            "concept_gate_pool_min": 12,
                            "mastery_pool_min": 14,
                            "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
                        },
                    )
                    self.assertGreaterEqual(len(diagnostic_items), 14)
                    self.assertGreaterEqual(len(concept_checks), 12)
                    self.assertGreaterEqual(len(mastery_items), 14)
                    self.assertGreaterEqual(len(contract["worked_examples"]), 7)
                    self.assertGreaterEqual(len(contract["core_concepts"]), 8)
                    self.assertGreaterEqual(len(contract["reflection_prompts"]), 5)
                    self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 6)
                    self.assertGreaterEqual(len(contract.get("release_checks") or []), 8)
                    self.assertGreaterEqual(len(contract["technical_words"]), 4)
                    for entry in contract["technical_words"]:
                        self.assertTrue(entry["term"].strip())
                        self.assertTrue(entry["meaning"].strip())
                        self.assertNotIn(str(entry.get("source") or "").lower(), {"generated", "lesson_generated"})
                    self.assertGreaterEqual(len(lesson["phases"]["analogical_grounding"]["micro_prompts"]), 4)
                    self.assertGreaterEqual(len(lesson["phases"]["simulation_inquiry"]["inquiry_prompts"]), 4)
                    self.assertGreaterEqual(len(lesson["phases"]["concept_reconstruction"]["prompts"]), 4)

                    representation_kinds = {item["kind"] for item in contract["representations"]}
                    self.assertIn("words", representation_kinds)
                    self.assertIn("formula", representation_kinds)
                    self.assertIn("equation_story", representation_kinds)

                    self.assertTrue(simulation_contract["asset_id"])
                    self.assertTrue(simulation_contract["concept"])
                    self.assertTrue(simulation_contract["focus_prompt"])
                    self.assertGreaterEqual(len(simulation_contract["controls"]), 4)
                    self.assertGreaterEqual(len(simulation_contract["readouts"]), 4)
                    self.assertGreaterEqual(len(simulation_contract["comparison_tasks"]), 6)
                    self.assertIn("condition", simulation_contract["takeaway"].lower())
                    simulation_concepts.add(simulation_contract["concept"])
                    focus_prompts.add(simulation_contract["focus_prompt"])

                    self.assertEqual(lesson["sim"]["depth"], "advanced")
                    self.assertIn("comparison_mode", lesson["sim"]["fields"])
                    self.assertGreaterEqual(len(lesson["sim"]["instructions"]), 6)
                    self.assertGreaterEqual(len(lesson["sim"]["outcomes"]), 7)

                    self.assertEqual(sim_lab["depth"], "advanced")
                    self.assertIn("comparison_mode", sim_lab["fields"])
                    self.assertGreaterEqual(len(sim_lab["instructions"]), 6)
                    self.assertGreaterEqual(len(sim_lab["outcomes"]), 7)

                    skill_tags = set()
                    all_items = [*diagnostic_items, *concept_checks, *mastery_items]
                    for question in all_items:
                        if question["type"] == "short":
                            accepted = question.get("accepted_answers") or []
                            if accepted and not all(str(answer).strip().isdigit() for answer in accepted):
                                self.assertIn("phrase_groups", question.get("acceptance_rules", {}))
                        self.assertTrue(question.get("skill_tags"))
                        skill_tags.update(question.get("skill_tags") or [])
                    self.assertGreaterEqual(len(skill_tags), 4)

                self.assertEqual(len(simulation_concepts), 6)
                self.assertEqual(len(focus_prompts), 6)

    def test_a6_to_a11_lessons_balance_mechanism_and_formal_rigour(self) -> None:
        formal_tokens = ("relation", "equation", "unit", "units", "condition", "valid", "si", "formula")
        explanation_tokens = ("why", "explain", "which mechanism", "what distinction", "rigorous", "best protects", "summary")

        for module_id, (_, lessons, _, _) in MODULES.items():
            for lesson_id, lesson in lessons:
                with self.subTest(module_id=module_id, lesson_id=lesson_id):
                    diagnostic_items = lesson["phases"]["diagnostic"]["items"]
                    concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
                    mastery_items = lesson["phases"]["transfer"]["items"]
                    all_items = [*diagnostic_items, *concept_checks, *mastery_items]
                    prompts = [str(item.get("prompt") or "").lower() for item in all_items]

                    short_count = sum(1 for item in all_items if item.get("type") == "short")
                    formal_count = sum(1 for prompt in prompts if any(token in prompt for token in formal_tokens))
                    explanation_count = sum(1 for prompt in prompts if any(token in prompt for token in explanation_tokens))
                    mastery_short_count = sum(1 for item in mastery_items if item.get("type") == "short")

                    self.assertGreaterEqual(short_count, 8, lesson_id)
                    self.assertGreaterEqual(formal_count, 8, lesson_id)
                    self.assertGreaterEqual(explanation_count, 8, lesson_id)
                    self.assertGreaterEqual(mastery_short_count, 3, lesson_id)


if __name__ == "__main__":
    unittest.main()
