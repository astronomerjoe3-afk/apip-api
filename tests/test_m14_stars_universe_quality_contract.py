import unittest

from scripts.seed_m14_stars_universe_module import M14_LESSONS, M14_MODULE_DOC, M14_SIM_LABS


class M14StarsUniverseQualityContractTests(unittest.TestCase):
    def test_m14_stars_bundle_uses_v3_contract_and_generated_assets(self) -> None:
        self.assertEqual(M14_MODULE_DOC["id"], "M14")
        self.assertEqual(M14_MODULE_DOC["title"], "Stars and the Universe")
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
            self.assertGreaterEqual(len(contract["technical_words"]), 4)
            self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 4)
            self.assertTrue(contract.get("scaffold_support"))
            self.assertTrue(simulation_contract["asset_id"])
            self.assertTrue(simulation_contract["concept"])
            self.assertTrue(simulation_contract["focus_prompt"])
            self.assertTrue(simulation_contract["baseline_case"])
            self.assertGreaterEqual(len(simulation_contract["controls"]), 3)
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
                        self.assertIn("phrase_groups", question.get("acceptance_rules", {}))
                self.assertTrue(question.get("skill_tags"))
                skill_tags.update(question.get("skill_tags") or [])
            self.assertGreaterEqual(len(skill_tags), 4)

        self.assertEqual(len(simulation_concepts), 6)
        self.assertEqual(len(focus_prompts), 6)

    def test_m14_lesson_three_includes_authored_technical_words(self) -> None:
        lesson = dict(M14_LESSONS)["M14_L3"]
        technical_words = lesson["authoring_contract"]["technical_words"]
        terms = {entry["term"] for entry in technical_words}

        self.assertIn("Galaxy", terms)
        self.assertIn("Milky Way", terms)
        self.assertIn("Solar System", terms)
        self.assertIn("Gravity-bound", terms)

    def test_m14_curriculum_scope_stays_on_universe_and_expansion(self) -> None:
        mastery_text = " ".join(M14_MODULE_DOC.get("mastery_outcomes") or []).lower()
        description_text = str(M14_MODULE_DOC.get("description") or "").lower()
        self.assertIn("fusion", mastery_text)
        self.assertIn("stellar lifecycle", mastery_text)
        self.assertIn("milky way", mastery_text)
        self.assertIn("light-year", mastery_text)
        self.assertIn("redshift", mastery_text)
        self.assertIn("big bang", mastery_text)
        self.assertIn("beacon-city", description_text)
        self.assertIn("stretchmap", description_text)
        self.assertNotIn("electric current", mastery_text)
        self.assertNotIn("half-life", mastery_text)
        self.assertNotIn("pressure", mastery_text)

    def test_m14_lessons_balance_conceptual_and_quantitative_reasoning(self) -> None:
        comparison_tokens = (
            "nm",
            "light-year",
            "light-years",
            "solar mass",
            "solar masses",
            "mass",
            "times farther",
            "larger",
            "smaller",
            "greater",
            "brighter",
            "brightness",
            "bright",
            "dim",
            "faint",
            "pair best contrasts",
            "contrast",
            "different",
            "later",
            "stable stage",
            "route",
            "scale",
            "distance",
            "wavelength",
            "redshift",
            "factor",
            "500",
            "650",
            "700",
            "100,000",
        )
        explanation_tokens = (
            "why",
            "explain",
            "summarize",
            "which statement",
            "strongest",
            "best protects",
            "what broad model",
        )

        for lesson_id, lesson in M14_LESSONS:
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            mastery_items = lesson["phases"]["transfer"]["items"]
            all_items = [*diagnostic_items, *concept_checks, *mastery_items]
            prompts = [str(item.get("prompt") or "").lower() for item in all_items]

            short_count = sum(1 for item in all_items if item.get("type") == "short")
            quantitative_count = sum(1 for prompt in prompts if any(token in prompt for token in comparison_tokens) or any(ch.isdigit() for ch in prompt))
            explanation_count = sum(1 for prompt in prompts if any(token in prompt for token in explanation_tokens))
            mastery_short_count = sum(1 for item in mastery_items if item.get("type") == "short")

            self.assertGreaterEqual(short_count, 6, lesson_id)
            self.assertGreaterEqual(quantitative_count, 4, lesson_id)
            self.assertGreaterEqual(explanation_count, 4, lesson_id)
            self.assertGreaterEqual(mastery_short_count, 2, lesson_id)

    def test_m14_star_brightness_short_answer_accepts_source_language(self) -> None:
        lesson = dict(M14_LESSONS)["M14_L1"]
        question = next(
            item
            for item in lesson["phases"]["diagnostic"]["items"]
            if item.get("id") == "M14L1_D8"
        )

        phrase_groups = question.get("acceptance_rules", {}).get("phrase_groups", [])
        flattened = {phrase for group in phrase_groups for phrase in group}

        self.assertIn("reflector", flattened)
        self.assertIn("source of light", flattened)
        self.assertIn("makes its own light", flattened)

    def test_m14_mastery_brightness_short_answer_accepts_concise_valid_wording(self) -> None:
        lesson = dict(M14_LESSONS)["M14_L1"]
        question = next(
            item
            for item in lesson["phases"]["transfer"]["items"]
            if item.get("id") == "M14L1_M9"
        )

        accepted = {str(answer) for answer in question.get("accepted_answers", [])}
        phrase_groups = question.get("acceptance_rules", {}).get("phrase_groups", [])
        flattened = {phrase for group in phrase_groups for phrase in group}

        self.assertIn("Because both sources and reflectors can appear bright.", accepted)
        self.assertIn("Because both stars and reflective planets can appear bright.", accepted)
        self.assertIn("reflector", flattened)
        self.assertIn("reflective", flattened)
        self.assertIn("both", flattened)

    def test_m14_stellar_path_diagnostic_accepts_mass_determines_ending_wording(self) -> None:
        lesson = dict(M14_LESSONS)["M14_L2"]
        question = next(
            item
            for item in lesson["phases"]["diagnostic"]["items"]
            if item.get("id") == "M14L2_D9"
        )

        accepted = {str(answer) for answer in question.get("accepted_answers", [])}
        phrase_groups = question.get("acceptance_rules", {}).get("phrase_groups", [])
        flattened = {phrase for group in phrase_groups for phrase in group}

        self.assertIn("Because their mass determines their ending.", accepted)
        self.assertIn("Because a star's mass determines its ending.", accepted)
        self.assertIn("mass", flattened)
        self.assertIn("determines", flattened)
        self.assertIn("ending", flattened)


if __name__ == "__main__":
    unittest.main()
