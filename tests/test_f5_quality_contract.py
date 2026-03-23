import unittest

from scripts.revised_core_curriculum_modules import F5_LESSONS, F5_MODULE_DOC, F5_SIM_LABS


class F5QualityContractTests(unittest.TestCase):
    def test_f5_bundle_uses_v3_contract_and_lesson_owned_banks(self) -> None:
        self.assertEqual(F5_MODULE_DOC["id"], "F5")
        self.assertEqual(F5_MODULE_DOC["title"], "Observable Earth and Sky")
        self.assertEqual(F5_MODULE_DOC["authoring_standard"], "lesson_authoring_spec_v3")
        self.assertEqual(len(F5_LESSONS), 6)
        self.assertEqual(len(F5_SIM_LABS), 6)

        simulation_concepts = set()
        focus_prompts = set()

        for lesson_id, lesson in F5_LESSONS:
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
            self.assertGreaterEqual(len(contract["worked_examples"]), 3, lesson_id)
            self.assertGreaterEqual(len(contract["core_concepts"]), 4, lesson_id)
            self.assertGreaterEqual(len(contract["technical_words"]), 4, lesson_id)
            self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 4, lesson_id)
            self.assertTrue(contract.get("scaffold_support"), lesson_id)
            self.assertEqual(len(contract["visual_assets"]), 1, lesson_id)
            self.assertGreaterEqual(len(contract.get("animation_assets") or []), 1, lesson_id)
            self.assertEqual(len(lesson["generated_assets"]["diagrams"]), 1, lesson_id)
            self.assertGreaterEqual(len(lesson["generated_assets"]["animations"]), 1, lesson_id)
            self.assertIn("generated_lab", lesson["phases"]["simulation_inquiry"])
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
            self.assertTrue(any(kind in {"diagram", "graph", "table", "model"} for kind in representation_kinds))

            skill_tags = set()
            for question in [*diagnostic_items, *concept_checks, *mastery_items]:
                if question["type"] == "short":
                    accepted = question.get("accepted_answers") or []
                    if accepted and not all(str(answer).strip().isdigit() for answer in accepted):
                        self.assertIn("phrase_groups", question.get("acceptance_rules", {}), question["id"])
                skill_tags.update(question.get("skill_tags") or [])
            self.assertGreaterEqual(len(skill_tags), 4, lesson_id)

        self.assertEqual(len(simulation_concepts), 6)
        self.assertEqual(len(focus_prompts), 6)

    def test_f5_scope_stays_on_earth_sky_and_solar_system(self) -> None:
        mastery_text = " ".join(F5_MODULE_DOC.get("mastery_outcomes") or []).lower()
        description_text = str(F5_MODULE_DOC.get("description") or "").lower()

        self.assertIn("day and night", mastery_text)
        self.assertIn("seasons", mastery_text)
        self.assertIn("phases", mastery_text)
        self.assertIn("solar system", mastery_text)
        self.assertIn("lantern", description_text)
        self.assertIn("skycourt", description_text)
        self.assertNotIn("electrical circuit", mastery_text)
        self.assertNotIn("half-life", mastery_text)

    def test_f5_lessons_mix_explanation_with_qualitative_or_scale_reasoning(self) -> None:
        comparison_tokens = (
            "24",
            "365",
            "half",
            "quarter",
            "six months",
            "distance",
            "scale",
            "larger",
            "smaller",
            "closer",
            "farther",
            "lap",
            "orbit",
            "host",
            "phase",
            "hemisphere",
            "year",
            "day",
        )
        explanation_tokens = (
            "why",
            "explain",
            "which statement",
            "strongest",
            "best",
            "how is",
            "what is the most important correction",
        )

        for lesson_id, lesson in F5_LESSONS:
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            mastery_items = lesson["phases"]["transfer"]["items"]
            all_items = [*diagnostic_items, *concept_checks, *mastery_items]
            prompts = [str(item.get("prompt") or "").lower() for item in all_items]

            short_count = sum(1 for item in all_items if item.get("type") == "short")
            comparison_count = sum(
                1
                for prompt in prompts
                if any(token in prompt for token in comparison_tokens) or any(ch.isdigit() for ch in prompt)
            )
            explanation_count = sum(1 for prompt in prompts if any(token in prompt for token in explanation_tokens))
            mastery_short_count = sum(1 for item in mastery_items if item.get("type") == "short")

            self.assertGreaterEqual(short_count, 8, lesson_id)
            self.assertGreaterEqual(comparison_count, 4, lesson_id)
            self.assertGreaterEqual(explanation_count, 4, lesson_id)
            self.assertGreaterEqual(mastery_short_count, 4, lesson_id)

    def test_f5_day_night_short_answers_accept_rotation_wording(self) -> None:
        lesson = dict(F5_LESSONS)["F5_L2"]
        question = next(
            item
            for item in lesson["phases"]["transfer"]["items"]
            if item.get("id") == "F5L2_M10"
        )

        accepted = {str(answer) for answer in question.get("accepted_answers", [])}
        phrase_groups = question.get("acceptance_rules", {}).get("phrase_groups", [])
        flattened = {phrase for group in phrase_groups for phrase in group}

        self.assertIn("because the apparent daily motion is better explained by Earth rotating", accepted)
        self.assertIn("because the daily sky pattern is a viewpoint effect from Earth's spin", accepted)
        self.assertIn("rotate", flattened)
        self.assertIn("spin", flattened)
        self.assertIn("apparent", flattened)

    def test_f5_phase_short_answers_accept_viewing_angle_language(self) -> None:
        lesson = dict(F5_LESSONS)["F5_L4"]
        question = next(
            item
            for item in lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            if item.get("id") == "F5L4_C8"
        )

        phrase_groups = question.get("acceptance_rules", {}).get("phrase_groups", [])
        flattened = {phrase for group in phrase_groups for phrase in group}

        self.assertIn("lit half", flattened)
        self.assertIn("view", flattened)
        self.assertIn("sunlit", flattened)


if __name__ == "__main__":
    unittest.main()
