import unittest

from scripts.seed_a1_module import A1_LESSONS, A1_MODULE_DOC, A1_SIM_LABS
from scripts.seed_a2_module import A2_LESSONS, A2_MODULE_DOC, A2_SIM_LABS
from scripts.seed_a3_module import A3_LESSONS, A3_MODULE_DOC, A3_SIM_LABS
from scripts.seed_a4_module import A4_LESSONS, A4_MODULE_DOC, A4_SIM_LABS
from scripts.seed_a5_module import A5_LESSONS, A5_MODULE_DOC, A5_SIM_LABS


class A1A5QualityContractTests(unittest.TestCase):
    MODULE_CASES = [
        ("A1", A1_MODULE_DOC, A1_LESSONS, A1_SIM_LABS, "Matter, Radiation and Particles", ("charge", "baryon", "lepton", "photon", "energy", "momentum", "mev", "lambda")),
        ("A2", A2_MODULE_DOC, A2_LESSONS, A2_SIM_LABS, "Quantum Phenomena and Atomic Spectra", ("frequency", "energy", "threshold", "photoelectron", "wavelength", "ev", "hz", "lambda")),
        ("A3", A3_MODULE_DOC, A3_LESSONS, A3_SIM_LABS, "Advanced Waves and Optics", ("wavelength", "phase", "path", "frequency", "critical angle", "grating", "trace", "angle")),
        ("A4", A4_MODULE_DOC, A4_LESSONS, A4_SIM_LABS, "Advanced Mechanics and Materials", ("velocity", "acceleration", "projectile", "momentum", "radius", "stress", "strain", "young")),
        ("A5", A5_MODULE_DOC, A5_LESSONS, A5_SIM_LABS, "Oscillations", ("frequency", "period", "amplitude", "omega", "displacement", "acceleration", "energy", "damping")),
    ]

    def test_a1_a5_bundles_use_stronger_quality_contract(self) -> None:
        for module_id, module_doc, lessons, sim_labs, expected_title, _ in self.MODULE_CASES:
            doc_id = module_doc.get("id") or module_doc.get("module_id")
            self.assertEqual(doc_id, module_id)
            self.assertEqual(module_doc["title"], expected_title)
            self.assertEqual(module_doc["authoring_standard"], "lesson_authoring_spec_v3")
            self.assertEqual(len(lessons), 6)
            self.assertEqual(len(sim_labs), 6)

            simulation_concepts = set()
            focus_prompts = set()
            for lesson_id, lesson in lessons:
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
                self.assertGreaterEqual(len(diagnostic_items), 10, lesson_id)
                self.assertGreaterEqual(len(concept_checks), 8, lesson_id)
                self.assertGreaterEqual(len(mastery_items), 10, lesson_id)
                self.assertEqual(len(contract["visual_assets"]), 1, lesson_id)
                self.assertEqual(len(contract["animation_assets"]), 1, lesson_id)
                self.assertEqual(len(lesson["generated_assets"]["diagrams"]), 1, lesson_id)
                self.assertEqual(len(lesson["generated_assets"]["animations"]), 1, lesson_id)
                self.assertIn("generated_lab", lesson["phases"]["simulation_inquiry"], lesson_id)
                self.assertGreaterEqual(len(contract["worked_examples"]), 3, lesson_id)
                self.assertGreaterEqual(len(contract["core_concepts"]), 4, lesson_id)
                self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 4, lesson_id)
                self.assertIn(
                    "No picture labels, angle marks, or callouts clip on desktop or mobile layouts.",
                    contract["visual_clarity_checks"],
                    lesson_id,
                )
                self.assertTrue(simulation_contract["asset_id"], lesson_id)
                self.assertTrue(simulation_contract["concept"], lesson_id)
                self.assertTrue(simulation_contract["focus_prompt"], lesson_id)
                self.assertTrue(simulation_contract["baseline_case"], lesson_id)
                self.assertGreaterEqual(len(simulation_contract["controls"]), 3, lesson_id)
                self.assertGreaterEqual(len(simulation_contract["readouts"]), 3, lesson_id)
                self.assertGreaterEqual(len(simulation_contract["comparison_tasks"]), 2, lesson_id)
                simulation_concepts.add(simulation_contract["concept"])
                focus_prompts.add(simulation_contract["focus_prompt"])

                representation_kinds = {item["kind"] for item in contract["representations"]}
                self.assertIn("words", representation_kinds, lesson_id)
                self.assertIn("formula", representation_kinds, lesson_id)
                self.assertTrue(any(kind in {"diagram", "graph", "table", "model", "equation_story"} for kind in representation_kinds), lesson_id)

                skill_tags = set()
                for question in [*diagnostic_items, *concept_checks, *mastery_items]:
                    if question["type"] == "short":
                        accepted = question.get("accepted_answers") or []
                        if accepted and not all(str(answer).strip().isdigit() for answer in accepted):
                            self.assertIn("phrase_groups", question.get("acceptance_rules", {}), lesson_id)
                    self.assertTrue(question.get("skill_tags"), lesson_id)
                    skill_tags.update(question.get("skill_tags") or [])
                self.assertGreaterEqual(len(skill_tags), 4, lesson_id)

            self.assertEqual(len(simulation_concepts), 6, module_id)
            self.assertEqual(len(focus_prompts), 6, module_id)

    def test_a1_a5_lessons_balance_explanation_and_relation_work(self) -> None:
        explanation_tokens = ("why", "explain", "which statement", "best summary", "compare", "what mechanism", "what contrast")

        for module_id, _, lessons, _, _, quantitative_tokens in self.MODULE_CASES:
            for lesson_id, lesson in lessons:
                diagnostic_items = lesson["phases"]["diagnostic"]["items"]
                concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
                mastery_items = lesson["phases"]["transfer"]["items"]
                all_items = [*diagnostic_items, *concept_checks, *mastery_items]
                prompts = [str(item.get("prompt") or "").lower() for item in all_items]

                short_count = sum(1 for item in all_items if item.get("type") == "short")
                quantitative_count = sum(
                    1
                    for prompt in prompts
                    if any(token in prompt for token in quantitative_tokens) or any(ch.isdigit() for ch in prompt)
                )
                explanation_count = sum(1 for prompt in prompts if any(token in prompt for token in explanation_tokens))
                mastery_short_count = sum(1 for item in mastery_items if item.get("type") == "short")

                self.assertGreaterEqual(short_count, 4, f"{module_id}:{lesson_id}")
                self.assertGreaterEqual(quantitative_count, 4, f"{module_id}:{lesson_id}")
                self.assertGreaterEqual(explanation_count, 4, f"{module_id}:{lesson_id}")
                self.assertGreaterEqual(mastery_short_count, 3, f"{module_id}:{lesson_id}")


if __name__ == "__main__":
    unittest.main()
