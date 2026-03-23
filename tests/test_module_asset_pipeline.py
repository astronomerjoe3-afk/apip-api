from __future__ import annotations

import unittest

from app.services.catalog_bootstrap import get_catalog_module_ids, get_catalog_module_row
from scripts.module_asset_pipeline import plan_lesson_assets
from scripts.nextgen_module_builder import _question
from scripts.seed_f1_module import F1_LESSONS, F1_MODULE_DOC, F1_SIM_LABS
from scripts.seed_f4_module import F4_LESSONS, F4_MODULE_DOC, F4_SIM_LABS
from scripts.seed_m1_module import M1_LESSONS, M1_MODULE_DOC, M1_SIM_LABS
from scripts.seed_m2_module import M2_LESSONS, M2_MODULE_DOC, M2_SIM_LABS
from scripts.seed_m3_module import M3_LESSONS, M3_MODULE_DOC, M3_SIM_LABS
from scripts.seed_m4_module import M4_LESSONS, M4_MODULE_DOC, M4_SIM_LABS
from scripts.seed_m5_module import M5_LESSONS, M5_MODULE_DOC, M5_SIM_LABS
from scripts.seed_m6_module import M6_LESSONS, M6_MODULE_DOC, M6_SIM_LABS
from scripts.seed_m7_module import M7_LESSONS, M7_MODULE_DOC, M7_SIM_LABS
from scripts.seed_m8_module import M8_LESSONS, M8_MODULE_DOC, M8_SIM_LABS
from scripts.seed_m9_module import M9_LESSONS, M9_MODULE_DOC, M9_SIM_LABS
from scripts.seed_m10_module import M10_LESSONS, M10_MODULE_DOC, M10_SIM_LABS
from scripts.seed_m11_module import M11_LESSONS, M11_MODULE_DOC, M11_SIM_LABS
from scripts.seed_m12_module import M12_LESSONS, M12_MODULE_DOC, M12_SIM_LABS
from scripts.seed_m13_module import M13_LESSONS, M13_MODULE_DOC, M13_SIM_LABS
from scripts.seed_a1_module import A1_LESSONS, A1_MODULE_DOC, A1_SIM_LABS
from scripts.seed_a2_module import A2_LESSONS, A2_MODULE_DOC, A2_SIM_LABS
from scripts.seed_a3_module import A3_LESSONS, A3_MODULE_DOC, A3_SIM_LABS
from scripts.seed_a5_module import A5_LESSONS, A5_MODULE_DOC, A5_SIM_LABS
from scripts.revised_core_curriculum_modules import F5_MODULE_DOC, F5_LESSONS, F5_SIM_LABS, M14_MODULE_DOC as REVISED_M14_MODULE_DOC, M14_LESSONS as REVISED_M14_LESSONS, M14_SIM_LABS as REVISED_M14_SIM_LABS


class ModuleAssetPipelineTests(unittest.TestCase):
    def test_catalog_bootstrap_includes_f5_bundle(self) -> None:
        self.assertIn("F5", get_catalog_module_ids())

        row = get_catalog_module_row("F5")
        self.assertIsNotNone(row)
        self.assertEqual(row["id"], "F5")
        self.assertEqual(row["title"], "Observable Earth and Sky")

    def test_catalog_bootstrap_includes_m12_bundle(self) -> None:
        self.assertIn("M12", get_catalog_module_ids())

        row = get_catalog_module_row("M12")
        self.assertIsNotNone(row)
        self.assertEqual(row["id"], "M12")
        self.assertEqual(row["title"], "Nuclear Energy and Applications")

    def test_catalog_bootstrap_includes_a1_bundle(self) -> None:
        self.assertIn("A1", get_catalog_module_ids())

        row = get_catalog_module_row("A1")
        self.assertIsNotNone(row)
        self.assertEqual(row["id"], "A1")
        self.assertEqual(row["title"], "Matter, Radiation and Particles")

    def test_catalog_bootstrap_includes_a2_bundle(self) -> None:
        self.assertIn("A2", get_catalog_module_ids())

        row = get_catalog_module_row("A2")
        self.assertIsNotNone(row)
        self.assertEqual(row["id"], "A2")
        self.assertEqual(row["title"], "Quantum Phenomena and Atomic Spectra")

    def test_catalog_bootstrap_includes_a3_bundle(self) -> None:
        self.assertIn("A3", get_catalog_module_ids())

        row = get_catalog_module_row("A3")
        self.assertIsNotNone(row)
        self.assertEqual(row["id"], "A3")
        self.assertEqual(row["title"], "Advanced Waves and Optics")

    def test_catalog_bootstrap_includes_a5_bundle(self) -> None:
        self.assertIn("A5", get_catalog_module_ids())

        row = get_catalog_module_row("A5")
        self.assertIsNotNone(row)
        self.assertEqual(row["id"], "A5")
        self.assertEqual(row["title"], "Oscillations")

    def test_catalog_bootstrap_excludes_m15_bundle(self) -> None:
        self.assertNotIn("M15", get_catalog_module_ids())
        self.assertIsNone(get_catalog_module_row("M15"))

    def test_revised_m14_bundle_uses_generated_assets_and_space_contracts(self) -> None:
        self.assertEqual(REVISED_M14_MODULE_DOC["id"], "M14")
        self.assertEqual(REVISED_M14_MODULE_DOC["title"], "Stars and the Universe")
        self.assertEqual(REVISED_M14_MODULE_DOC["authoring_standard"], "lesson_authoring_spec_v3")
        self.assertEqual(len(REVISED_M14_LESSONS), 6)
        self.assertEqual(len(REVISED_M14_SIM_LABS), 6)

        for _, lesson in REVISED_M14_LESSONS:
            contract = lesson["authoring_contract"]
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            transfer_items = lesson["phases"]["transfer"]["items"]
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
            self.assertGreaterEqual(len(transfer_items), 10)
            self.assertEqual(len(contract["visual_assets"]), 1)
            self.assertEqual(contract["visual_assets"][0]["template"], "space_astrophysics_diagram")
            self.assertIn("generated_lab", lesson["phases"]["simulation_inquiry"])
            self.assertGreaterEqual(len(contract["worked_examples"]), 3)
            self.assertGreaterEqual(len(contract["core_concepts"]), 4)
            self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 3)
            simulation_contract = contract["simulation_contract"]
            self.assertTrue(simulation_contract["asset_id"])
            self.assertTrue(simulation_contract["concept"])
            self.assertTrue(simulation_contract["focus_prompt"])
            self.assertGreaterEqual(len(simulation_contract["controls"]), 3)
            self.assertGreaterEqual(len(simulation_contract["readouts"]), 3)

            skill_tags = set()
            for question in [*diagnostic_items, *concept_checks, *transfer_items]:
                if question["type"] == "short":
                    accepted = question.get("accepted_answers") or []
                    if accepted and not all(str(answer).strip().isdigit() for answer in accepted) and question.get("acceptance_rules"):
                        self.assertIn("phrase_groups", question.get("acceptance_rules", {}))
                self.assertTrue(question.get("skill_tags"))
                skill_tags.update(question.get("skill_tags") or [])
            self.assertGreaterEqual(len(skill_tags), 4)

    def test_revised_m14_curriculum_scope_stays_on_universe_and_expansion(self) -> None:
        mastery_text = " ".join(REVISED_M14_MODULE_DOC.get("mastery_outcomes") or []).lower()
        description_text = str(REVISED_M14_MODULE_DOC.get("description") or "").lower()
        self.assertIn("star", mastery_text)
        self.assertIn("milky way", mastery_text)
        self.assertIn("light-year", mastery_text)
        self.assertIn("redshift", mastery_text)
        self.assertIn("big bang", mastery_text)
        self.assertIn("beacon-city", description_text)
        self.assertIn("stretchmap", description_text)
        self.assertNotIn("electric current", mastery_text)
        self.assertNotIn("half-life", mastery_text)

    def test_f5_bundle_uses_lesson_owned_banks_and_astronomy_visuals(self) -> None:
        self.assertEqual(F5_MODULE_DOC["id"], "F5")
        self.assertEqual(F5_MODULE_DOC["title"], "Observable Earth and Sky")
        self.assertEqual(F5_MODULE_DOC["authoring_standard"], "lesson_authoring_spec_v3")
        self.assertEqual(F5_MODULE_DOC["content_version"], "20260323_f5_lantern_ring_skycourt_v2")
        self.assertEqual(len(F5_LESSONS), 6)
        self.assertEqual(len(F5_SIM_LABS), 6)

        simulation_concepts = set()
        focus_prompts = set()
        for _, lesson in F5_LESSONS:
            contract = lesson["authoring_contract"]
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            transfer_items = lesson["phases"]["transfer"]["items"]
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
            self.assertGreaterEqual(len(transfer_items), 10)
            self.assertEqual(len(contract["visual_assets"]), 1)
            self.assertEqual(len(contract["animation_assets"]), 1)
            self.assertIn(contract["visual_assets"][0]["template"], {"astronomy_diagram", "space_astrophysics_diagram"})
            self.assertNotEqual(contract["visual_assets"][0]["template"], "general_visual")
            self.assertIn("generated_lab", lesson["phases"]["simulation_inquiry"])
            self.assertGreaterEqual(len(contract["worked_examples"]), 3)
            self.assertGreaterEqual(len(contract["core_concepts"]), 4)
            self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 3)
            self.assertIn(
                "No picture labels, angle marks, or callouts clip on desktop or mobile layouts.",
                contract["visual_clarity_checks"],
            )
            self.assertTrue(simulation_contract["asset_id"])
            self.assertTrue(simulation_contract["concept"])
            self.assertTrue(simulation_contract["focus_prompt"])
            self.assertGreaterEqual(len(simulation_contract["controls"]), 3)
            self.assertGreaterEqual(len(simulation_contract["readouts"]), 3)
            self.assertGreaterEqual(len(simulation_contract["comparison_tasks"]), 2)
            simulation_concepts.add(simulation_contract["concept"])
            focus_prompts.add(simulation_contract["focus_prompt"])

            skill_tags = set()
            for question in [*diagnostic_items, *concept_checks, *transfer_items]:
                if question["type"] == "short":
                    accepted = question.get("accepted_answers") or []
                    if accepted and not all(str(answer).strip().isdigit() for answer in accepted) and question.get("acceptance_rules"):
                        self.assertIn("phrase_groups", question.get("acceptance_rules", {}))
                self.assertTrue(question.get("skill_tags"))
                skill_tags.update(question.get("skill_tags") or [])
            self.assertGreaterEqual(len(skill_tags), 4)

        self.assertEqual(len(simulation_concepts), 6)
        self.assertEqual(len(focus_prompts), 6)

    def test_a5_bundle_uses_v3_contract_and_generated_assets(self) -> None:
        self.assertEqual(A5_MODULE_DOC["id"], "A5")
        self.assertEqual(A5_MODULE_DOC["title"], "Oscillations")
        self.assertEqual(len(A5_LESSONS), 6)
        self.assertEqual(len(A5_SIM_LABS), 6)

        for _, lesson in A5_LESSONS:
            contract = lesson["authoring_contract"]
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            transfer_items = lesson["phases"]["transfer"]["items"]
            self.assertEqual(
                contract["assessment_bank_targets"],
                {
                    "diagnostic_pool_min": 6,
                    "concept_gate_pool_min": 4,
                    "mastery_pool_min": 6,
                    "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
                },
            )
            self.assertGreaterEqual(len(diagnostic_items), 6)
            self.assertGreaterEqual(len(concept_checks), 4)
            self.assertGreaterEqual(len(transfer_items), 6)
            self.assertEqual(len(contract["visual_assets"]), 1)
            self.assertEqual(len(contract["animation_assets"]), 1)
            self.assertIn("generated_lab", lesson["phases"]["simulation_inquiry"])

    def test_builder_question_accepts_type_field_for_mcq_specs(self) -> None:
        question = _question(
            {
                "id": "M3_LX_D1",
                "type": "mcq",
                "prompt": "Which store increases?",
                "choices": ["Height Store", "Leak Trail", "Nothing", "Charge"],
                "answer_index": 0,
                "hint": "Use the lesson story, not random labels.",
                "misconception_tags": ["energy_force_confusion"],
            },
            ["energy_force_confusion"],
        )

        self.assertEqual(question["type"], "mcq")
        self.assertEqual(question["choices"][0], "Height Store")
        self.assertEqual(question["misconception_tags"], ["energy_force_confusion"])

    def test_plan_lesson_assets_uses_simulation_contract_concept(self) -> None:
        lesson = {
            "lesson_id": "M3_LX",
            "module_id": "M3",
            "title": "Network Rules",
            "phases": {
                "analogical_grounding": {},
                "simulation_inquiry": {
                    "lab_id": "m3_network_rules_lab",
                },
            },
            "authoring_contract": {
                "visual_assets": [],
                "animation_assets": [],
                "simulation_contract": {
                    "asset_id": "m3_lx_network_rules_lab",
                    "concept": "series_parallel",
                    "baseline_case": "Start with one branch.",
                    "comparison_tasks": ["Add a second branch.", "Increase one resistance."],
                    "watch_for": "Keep route structure separate from resistance.",
                    "takeaway": "Series and parallel are different path stories.",
                },
            },
        }
        sim_lab = {
            "lab_id": "m3_network_rules_lab",
            "title": "Network Rules Lab",
            "description": "Interactive network comparison.",
        }

        compiled = plan_lesson_assets(lesson, sim_lab, public_base="/lesson_assets")

        simulation = compiled["generated_assets"]["simulation"]
        self.assertEqual(simulation["concept"], "series_parallel")
        self.assertEqual(
            simulation["public_url"],
            "/lesson_assets/M3/M3_LX/simulations/m3_network_rules_lab/index.html",
        )

    def test_m3_bundle_includes_planned_generated_assets(self) -> None:
        self.assertEqual(M3_MODULE_DOC["id"], "M3")
        self.assertEqual(M3_MODULE_DOC["title"], "Momentum, Work, Energy and Power")
        self.assertEqual(M3_MODULE_DOC["authoring_standard"], "lesson_authoring_spec_v2")
        self.assertEqual(len(M3_LESSONS), 6)
        self.assertEqual(len(M3_SIM_LABS), 6)
        self.assertEqual(
            [lesson_id for lesson_id, _ in M3_LESSONS],
            ["M3_L1", "M3_L2", "M3_L3", "M3_L4", "M3_L5", "M3_L6"],
        )

        lesson_id, lesson = M3_LESSONS[0]
        self.assertEqual(lesson_id, "M3_L1")
        self.assertIn("generated_assets", lesson)
        self.assertEqual(len(lesson["generated_assets"]["diagrams"]), 1)
        self.assertEqual(len(lesson["generated_assets"]["animations"]), 1)
        self.assertEqual(
            lesson["phases"]["simulation_inquiry"]["generated_lab"]["url"],
            "/lesson_assets/M3/M3_L1/simulations/m3_lift_launch_ledger_lab/index.html",
        )

    def test_m3_v3_contract_includes_richer_scaffold_support_and_answer_reasons(self) -> None:
        for _, lesson in M3_LESSONS:
            contract = lesson["authoring_contract"]
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            transfer_items = lesson["phases"]["transfer"]["items"]
            simulation_contract = contract["simulation_contract"]
            self.assertEqual(
                contract["assessment_bank_targets"],
                {
                    "diagnostic_pool_min": 8,
                    "concept_gate_pool_min": 6,
                    "mastery_pool_min": 8,
                    "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
                },
            )
            self.assertGreaterEqual(len(diagnostic_items), 8)
            self.assertGreaterEqual(len(concept_checks), 6)
            self.assertGreaterEqual(len(transfer_items), 8)
            scaffold_support = contract["scaffold_support"]
            self.assertTrue(scaffold_support["core_idea"])
            self.assertTrue(scaffold_support["reasoning"])
            self.assertTrue(scaffold_support["check_for_understanding"])
            self.assertTrue(scaffold_support["common_trap"])
            self.assertTrue(scaffold_support["analogy_bridge"]["body"])
            self.assertTrue(scaffold_support["analogy_bridge"]["check_for_understanding"])
            self.assertGreaterEqual(len(scaffold_support["extra_sections"]), 2)
            self.assertGreaterEqual(len(contract["worked_examples"]), 3)
            self.assertGreaterEqual(len(contract["core_concepts"]), 4)
            self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 3)
            self.assertTrue(simulation_contract["asset_id"])
            self.assertTrue(simulation_contract["concept"])
            self.assertTrue(simulation_contract["focus_prompt"])
            self.assertTrue(simulation_contract["baseline_case"])
            self.assertGreaterEqual(len(simulation_contract["controls"]), 3)
            self.assertGreaterEqual(len(simulation_contract["readouts"]), 3)
            self.assertGreaterEqual(len(simulation_contract["comparison_tasks"]), 2)

            for example in contract["worked_examples"]:
                self.assertTrue(example["answer_reason"])

            skill_tags = set()
            for question in [*diagnostic_items, *concept_checks, *transfer_items]:
                if question["type"] == "short":
                    accepted = question.get("accepted_answers") or []
                    if accepted and not all(str(answer).strip().isdigit() for answer in accepted) and question.get("acceptance_rules"):
                        self.assertIn("phrase_groups", question.get("acceptance_rules", {}))
                self.assertTrue(question.get("skill_tags"))
                skill_tags.update(question.get("skill_tags") or [])
            self.assertGreaterEqual(len(skill_tags), 4)

    def test_m3_curriculum_scope_stays_on_energy_work_and_power(self) -> None:
        mastery_text = " ".join(M3_MODULE_DOC.get("mastery_outcomes") or []).lower()
        description_text = str(M3_MODULE_DOC.get("description") or "").lower()
        self.assertIn("momentum", description_text)
        self.assertIn("work", description_text)
        self.assertIn("kinetic energy", mastery_text)
        self.assertIn("gravitational potential energy", mastery_text)
        self.assertIn("power", mastery_text)
        self.assertIn("efficiency", mastery_text)
        self.assertIn("ledger", description_text)
        self.assertIn("hand-off", description_text)
        self.assertNotIn("current", mastery_text)
        self.assertNotIn("resistance", mastery_text)
        self.assertNotIn("circuit", mastery_text)

    def test_m4_bundle_uses_lesson_owned_banks_and_generated_assets(self) -> None:
        self.assertEqual(M4_MODULE_DOC["id"], "M4")
        self.assertEqual(M4_MODULE_DOC["title"], "Materials, Density and Pressure")
        self.assertEqual(M4_MODULE_DOC["authoring_standard"], "lesson_authoring_spec_v2")
        self.assertEqual(len(M4_LESSONS), 6)
        self.assertEqual(len(M4_SIM_LABS), 6)
        self.assertEqual(
            [lesson_id for lesson_id, _ in M4_LESSONS],
            ["M4_L1", "M4_L2", "M4_L3", "M4_L4", "M4_L5", "M4_L6"],
        )

        for _, lesson in M4_LESSONS:
            contract = lesson["authoring_contract"]
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            transfer_items = lesson["phases"]["transfer"]["items"]
            simulation_contract = contract["simulation_contract"]
            self.assertEqual(
                contract["assessment_bank_targets"],
                {
                    "diagnostic_pool_min": 8,
                    "concept_gate_pool_min": 6,
                    "mastery_pool_min": 8,
                    "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
                },
            )
            self.assertGreaterEqual(len(diagnostic_items), 8)
            self.assertGreaterEqual(len(concept_checks), 6)
            self.assertGreaterEqual(len(transfer_items), 8)
            self.assertEqual(len(contract["visual_assets"]), 1)
            self.assertEqual(len(contract["animation_assets"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["diagrams"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["animations"]), 1)
            self.assertIn("generated_lab", lesson["phases"]["simulation_inquiry"])
            self.assertGreaterEqual(len(contract["worked_examples"]), 3)
            self.assertGreaterEqual(len(contract["core_concepts"]), 4)
            self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 3)
            self.assertTrue(simulation_contract["asset_id"])
            self.assertTrue(simulation_contract["concept"])
            self.assertTrue(simulation_contract["focus_prompt"])
            self.assertTrue(simulation_contract["baseline_case"])
            self.assertGreaterEqual(len(simulation_contract["controls"]), 3)
            self.assertGreaterEqual(len(simulation_contract["readouts"]), 3)
            self.assertGreaterEqual(len(simulation_contract["comparison_tasks"]), 2)

            scaffold_support = contract["scaffold_support"]
            self.assertTrue(scaffold_support["core_idea"])
            self.assertTrue(scaffold_support["reasoning"])
            self.assertTrue(scaffold_support["common_trap"])
            self.assertGreaterEqual(len(scaffold_support["extra_sections"]), 2)

            for example in contract["worked_examples"]:
                self.assertTrue(example["answer_reason"])

            skill_tags = set()
            for question in [*diagnostic_items, *concept_checks, *transfer_items]:
                if question["type"] == "short":
                    accepted = question.get("accepted_answers") or []
                    if accepted and not all(str(answer).strip().isdigit() for answer in accepted) and question.get("acceptance_rules"):
                        self.assertIn("phrase_groups", question.get("acceptance_rules", {}))
                self.assertTrue(question.get("skill_tags"))
                skill_tags.update(question.get("skill_tags") or [])
            self.assertGreaterEqual(len(skill_tags), 4)

    def test_m4_curriculum_scope_stays_on_pressure(self) -> None:
        mastery_text = " ".join(M4_MODULE_DOC.get("mastery_outcomes") or []).lower()
        description_text = str(M4_MODULE_DOC.get("description") or "").lower()
        self.assertIn("density", description_text)
        self.assertIn("pressure in solids", mastery_text)
        self.assertIn("liquid pressure", mastery_text)
        self.assertIn("atmospheric pressure", mastery_text)
        self.assertIn("solids", description_text)
        self.assertIn("liquids", description_text)
        self.assertIn("gases", description_text)
        self.assertIn("atmospheric", description_text)
        self.assertIn("liquid", description_text)
        self.assertIn("atmospheric", mastery_text)
        self.assertNotIn("patch-dome", description_text)
        self.assertNotIn("momentum", mastery_text)
        self.assertNotIn("current", mastery_text)
        self.assertNotIn("kinetic energy", mastery_text)

    def test_m4_l4_balances_shape_misconception_with_numeric_same_depth_checks(self) -> None:
        lesson = next(payload for lesson_id, payload in M4_LESSONS if lesson_id == "M4_L4")
        concept_prompts = " ".join(
            str(item.get("prompt") or "")
            for item in lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
        )
        diagnostic_prompts = " ".join(str(item.get("prompt") or "") for item in lesson["phases"]["diagnostic"]["items"])
        mastery_prompts = " ".join(str(item.get("prompt") or "") for item in lesson["phases"]["transfer"]["items"])

        self.assertIn("2.5 m below the surface", concept_prompts)
        self.assertIn("3 m below the surface", diagnostic_prompts)
        self.assertIn("2 m below the water surface", mastery_prompts)
        self.assertIn("ρ = 1000 kg/m^3", concept_prompts)
        self.assertIn("ρ = 1000 kg/m^3", diagnostic_prompts)
        self.assertIn("ρ = 1000 kg/m^3", mastery_prompts)

    def test_m5_bundle_uses_v3_contract_and_generated_assets(self) -> None:
        self.assertEqual(M5_MODULE_DOC["id"], "M5")
        self.assertEqual(M5_MODULE_DOC["title"], "Particle Model and Internal Energy")
        self.assertEqual(M5_MODULE_DOC["authoring_standard"], "lesson_authoring_spec_v3")
        self.assertEqual(len(M5_LESSONS), 6)
        self.assertEqual(len(M5_SIM_LABS), 6)
        self.assertEqual(
            [lesson_id for lesson_id, _ in M5_LESSONS],
            ["M5_L1", "M5_L2", "M5_L3", "M5_L4", "M5_L5", "M5_L6"],
        )

        simulation_concepts = set()
        focus_prompts = set()
        for _, lesson in M5_LESSONS:
            contract = lesson["authoring_contract"]
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            transfer_items = lesson["phases"]["transfer"]["items"]
            simulation_contract = contract["simulation_contract"]
            self.assertEqual(
                contract["assessment_bank_targets"],
                {
                    "diagnostic_pool_min": 8,
                    "concept_gate_pool_min": 6,
                    "mastery_pool_min": 8,
                    "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
                },
            )
            self.assertGreaterEqual(len(diagnostic_items), 8)
            self.assertGreaterEqual(len(concept_checks), 6)
            self.assertGreaterEqual(len(transfer_items), 8)
            self.assertEqual(len(contract["visual_assets"]), 1)
            self.assertEqual(len(contract["animation_assets"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["diagrams"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["animations"]), 1)
            self.assertIn("generated_lab", lesson["phases"]["simulation_inquiry"])
            self.assertGreaterEqual(len(contract["worked_examples"]), 3)
            self.assertGreaterEqual(len(contract["core_concepts"]), 4)
            self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 3)
            self.assertTrue(simulation_contract["asset_id"])
            self.assertTrue(simulation_contract["concept"])
            self.assertTrue(simulation_contract["focus_prompt"])
            self.assertTrue(simulation_contract["baseline_case"])
            self.assertGreaterEqual(len(simulation_contract["controls"]), 3)
            self.assertGreaterEqual(len(simulation_contract["readouts"]), 3)
            self.assertGreaterEqual(len(simulation_contract["comparison_tasks"]), 2)
            simulation_concepts.add(simulation_contract["concept"])
            focus_prompts.add(simulation_contract["focus_prompt"])

            scaffold_support = contract["scaffold_support"]
            self.assertTrue(scaffold_support["core_idea"])
            self.assertTrue(scaffold_support["reasoning"])
            self.assertTrue(scaffold_support["common_trap"])
            self.assertGreaterEqual(len(scaffold_support["extra_sections"]), 2)

            for example in contract["worked_examples"]:
                self.assertTrue(example["answer_reason"])

            skill_tags = set()
            for question in [*diagnostic_items, *concept_checks, *transfer_items]:
                if question["type"] == "short":
                    accepted = question.get("accepted_answers") or []
                    if accepted and not all(str(answer).strip().isdigit() for answer in accepted):
                        self.assertIn("phrase_groups", question.get("acceptance_rules", {}))
                self.assertTrue(question.get("skill_tags"))
                skill_tags.update(question.get("skill_tags") or [])
            self.assertGreaterEqual(len(skill_tags), 4)

        self.assertEqual(len(simulation_concepts), 6)
        self.assertEqual(len(focus_prompts), 6)

    def test_m5_curriculum_scope_stays_on_particle_model(self) -> None:
        mastery_text = " ".join(M5_MODULE_DOC.get("mastery_outcomes") or []).lower()
        description_text = str(M5_MODULE_DOC.get("description") or "").lower()
        self.assertIn("states of matter", description_text)
        self.assertIn("brownian motion", description_text)
        self.assertIn("temperature", description_text)
        self.assertIn("internal energy", description_text)
        self.assertIn("brownian motion", mastery_text)
        self.assertIn("temperature", mastery_text)
        self.assertIn("internal energy", mastery_text)
        self.assertNotIn("pressure", mastery_text)
        self.assertNotIn("current", mastery_text)
        self.assertNotIn("momentum", mastery_text)

    def test_m6_bundle_uses_v3_contract_and_generated_assets(self) -> None:
        self.assertEqual(M6_MODULE_DOC["id"], "M6")
        self.assertEqual(M6_MODULE_DOC["title"], "Thermal Transfer and Gas Behaviour")
        self.assertEqual(M6_MODULE_DOC["authoring_standard"], "lesson_authoring_spec_v3")
        self.assertEqual(len(M6_LESSONS), 6)
        self.assertEqual(len(M6_SIM_LABS), 6)
        self.assertEqual(
            [lesson_id for lesson_id, _ in M6_LESSONS],
            ["M6_L1", "M6_L2", "M6_L3", "M6_L4", "M6_L5", "M6_L6"],
        )

        simulation_concepts = set()
        focus_prompts = set()
        for _, lesson in M6_LESSONS:
            contract = lesson["authoring_contract"]
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            transfer_items = lesson["phases"]["transfer"]["items"]
            simulation_contract = contract["simulation_contract"]
            self.assertEqual(
                contract["assessment_bank_targets"],
                {
                    "diagnostic_pool_min": 8,
                    "concept_gate_pool_min": 6,
                    "mastery_pool_min": 8,
                    "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
                },
            )
            self.assertGreaterEqual(len(diagnostic_items), 8)
            self.assertGreaterEqual(len(concept_checks), 6)
            self.assertGreaterEqual(len(transfer_items), 8)
            self.assertEqual(len(contract["visual_assets"]), 1)
            self.assertEqual(len(contract["animation_assets"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["diagrams"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["animations"]), 1)
            self.assertIn("generated_lab", lesson["phases"]["simulation_inquiry"])
            self.assertGreaterEqual(len(contract["worked_examples"]), 3)
            self.assertGreaterEqual(len(contract["core_concepts"]), 4)
            self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 3)
            self.assertTrue(simulation_contract["asset_id"])
            self.assertTrue(simulation_contract["concept"])
            self.assertTrue(simulation_contract["focus_prompt"])
            simulation_concepts.add(simulation_contract["concept"])
            focus_prompts.add(simulation_contract["focus_prompt"])

            scaffold_support = contract["scaffold_support"]
            self.assertTrue(scaffold_support["core_idea"])
            self.assertTrue(scaffold_support["reasoning"])
            self.assertTrue(scaffold_support["common_trap"])
            self.assertGreaterEqual(len(scaffold_support["extra_sections"]), 2)

            for example in contract["worked_examples"]:
                self.assertTrue(example["answer_reason"])

            skill_tags = set()
            for question in [*diagnostic_items, *concept_checks, *transfer_items]:
                if question["type"] == "short":
                    accepted = question.get("accepted_answers") or []
                    if accepted and not all(str(answer).strip().isdigit() for answer in accepted) and question.get("acceptance_rules"):
                        self.assertIn("phrase_groups", question.get("acceptance_rules", {}))
                self.assertTrue(question.get("skill_tags"))
                skill_tags.update(question.get("skill_tags") or [])
            self.assertGreaterEqual(len(skill_tags), 3)

        self.assertEqual(len(simulation_concepts), 6)
        self.assertEqual(len(focus_prompts), 6)

    def test_m6_curriculum_scope_stays_on_thermal_properties_and_transfer(self) -> None:
        mastery_text = " ".join(M6_MODULE_DOC.get("mastery_outcomes") or []).lower()
        description_text = str(M6_MODULE_DOC.get("description") or "").lower()
        self.assertIn("gas", description_text)
        self.assertIn("specific heat capacity", description_text)
        self.assertIn("latent heat", description_text)
        self.assertIn("conduction", description_text)
        self.assertIn("convection", description_text)
        self.assertIn("radiation", description_text)
        self.assertIn("specific heat capacity", mastery_text)
        self.assertIn("latent heat", mastery_text)
        self.assertIn("conduction", mastery_text)
        self.assertIn("convection", mastery_text)
        self.assertIn("radiation", mastery_text)
        self.assertNotIn("pressure", mastery_text)
        self.assertNotIn("current", mastery_text)
        self.assertNotIn("momentum", mastery_text)

    def test_m7_bundle_uses_v3_contract_and_generated_assets(self) -> None:
        self.assertEqual(M7_MODULE_DOC["id"], "M7")
        self.assertEqual(M7_MODULE_DOC["title"], "Waves and Vibrations")
        self.assertEqual(M7_MODULE_DOC["authoring_standard"], "lesson_authoring_spec_v3")
        self.assertEqual(len(M7_LESSONS), 6)
        self.assertEqual(len(M7_SIM_LABS), 6)
        self.assertEqual(
            [lesson_id for lesson_id, _ in M7_LESSONS],
            ["M7_L1", "M7_L2", "M7_L3", "M7_L4", "M7_L5", "M7_L6"],
        )

        simulation_concepts = set()
        focus_prompts = set()
        for _, lesson in M7_LESSONS:
            contract = lesson["authoring_contract"]
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            transfer_items = lesson["phases"]["transfer"]["items"]
            simulation_contract = contract["simulation_contract"]
            self.assertEqual(
                contract["assessment_bank_targets"],
                {
                    "diagnostic_pool_min": 8,
                    "concept_gate_pool_min": 6,
                    "mastery_pool_min": 8,
                    "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
                },
            )
            self.assertGreaterEqual(len(diagnostic_items), 8)
            self.assertGreaterEqual(len(concept_checks), 6)
            self.assertGreaterEqual(len(transfer_items), 8)
            expected_visual_count = 1
            self.assertEqual(len(contract["visual_assets"]), expected_visual_count)
            self.assertEqual(len(contract["animation_assets"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["diagrams"]), expected_visual_count)
            self.assertEqual(len(lesson["generated_assets"]["animations"]), 1)
            self.assertIn("generated_lab", lesson["phases"]["simulation_inquiry"])
            self.assertGreaterEqual(len(contract["worked_examples"]), 3)
            self.assertGreaterEqual(len(contract["core_concepts"]), 4)
            self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 3)
            self.assertTrue(simulation_contract["asset_id"])
            self.assertTrue(simulation_contract["concept"])
            self.assertTrue(simulation_contract["focus_prompt"])
            self.assertTrue(simulation_contract["baseline_case"])
            self.assertGreaterEqual(len(simulation_contract["controls"]), 3)
            self.assertGreaterEqual(len(simulation_contract["readouts"]), 3)
            self.assertGreaterEqual(len(simulation_contract["comparison_tasks"]), 2)
            simulation_concepts.add(simulation_contract["concept"])
            focus_prompts.add(simulation_contract["focus_prompt"])

            scaffold_support = contract["scaffold_support"]
            self.assertTrue(scaffold_support["core_idea"])
            self.assertTrue(scaffold_support["reasoning"])
            self.assertTrue(scaffold_support["common_trap"])
            self.assertGreaterEqual(len(scaffold_support["extra_sections"]), 2)

            for example in contract["worked_examples"]:
                self.assertTrue(example["answer_reason"])

            skill_tags = set()
            for question in [*diagnostic_items, *concept_checks, *transfer_items]:
                if question["type"] == "short":
                    accepted = question.get("accepted_answers") or []
                    if accepted and not all(str(answer).strip().isdigit() for answer in accepted) and question.get("acceptance_rules"):
                        self.assertIn("phrase_groups", question.get("acceptance_rules", {}))
                self.assertTrue(question.get("skill_tags"))
                skill_tags.update(question.get("skill_tags") or [])
            self.assertGreaterEqual(len(skill_tags), 4)

        self.assertEqual(len(simulation_concepts), 6)
        self.assertEqual(len(focus_prompts), 6)

    def test_m7_curriculum_scope_stays_on_general_wave_properties(self) -> None:
        mastery_text = " ".join(M7_MODULE_DOC.get("mastery_outcomes") or []).lower()
        description_text = str(M7_MODULE_DOC.get("description") or "").lower()
        self.assertIn("vibrations", description_text)
        self.assertIn("transverse", mastery_text)
        self.assertIn("longitudinal", mastery_text)
        self.assertIn("reflection", mastery_text)
        self.assertIn("refraction", mastery_text)
        self.assertIn("diffraction", mastery_text)
        self.assertIn("travelling pattern", description_text)
        self.assertNotIn("pressure", mastery_text)
        self.assertNotIn("internal energy", mastery_text)
        self.assertNotIn("current", mastery_text)

    def test_m8_bundle_uses_v3_contract_and_generated_assets(self) -> None:
        self.assertEqual(M8_MODULE_DOC["id"], "M8")
        self.assertEqual(M8_MODULE_DOC["title"], "Light and Optics")
        self.assertEqual(M8_MODULE_DOC["authoring_standard"], "lesson_authoring_spec_v3")
        self.assertEqual(len(M8_LESSONS), 6)
        self.assertEqual(len(M8_SIM_LABS), 6)
        self.assertEqual(
            [lesson_id for lesson_id, _ in M8_LESSONS],
            ["M8_L1", "M8_L2", "M8_L3", "M8_L4", "M8_L5", "M8_L6"],
        )

        simulation_concepts = set()
        focus_prompts = set()
        for _, lesson in M8_LESSONS:
            contract = lesson["authoring_contract"]
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            transfer_items = lesson["phases"]["transfer"]["items"]
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
            self.assertGreaterEqual(len(transfer_items), 10)
            expected_visual_count = {
                "M8_L1": 5,
                "M8_L2": 1,
                "M8_L3": 1,
                "M8_L4": 1,
                "M8_L5": 2,
                "M8_L6": 3,
            }[lesson["lesson_id"]]
            self.assertEqual(len(contract["visual_assets"]), expected_visual_count)
            self.assertEqual(len(contract["animation_assets"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["diagrams"]), expected_visual_count)
            self.assertEqual(len(lesson["generated_assets"]["animations"]), 1)
            self.assertIn("generated_lab", lesson["phases"]["simulation_inquiry"])
            self.assertGreaterEqual(len(contract["worked_examples"]), 3)
            self.assertGreaterEqual(len(contract["core_concepts"]), 4)
            self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 3)
            self.assertTrue(simulation_contract["asset_id"])
            self.assertTrue(simulation_contract["concept"])
            self.assertTrue(simulation_contract["focus_prompt"])
            simulation_concepts.add(simulation_contract["concept"])
            focus_prompts.add(simulation_contract["focus_prompt"])

            scaffold_support = contract["scaffold_support"]
            self.assertTrue(scaffold_support["core_idea"])
            self.assertTrue(scaffold_support["reasoning"])
            self.assertTrue(scaffold_support["common_trap"])
            self.assertGreaterEqual(len(scaffold_support["extra_sections"]), 2)

            if lesson["lesson_id"] == "M8_L1":
                diagram_ids = {asset["asset_id"] for asset in lesson["generated_assets"]["diagrams"]}
                self.assertIn("m8-l1-surface-conversion", diagram_ids)
                self.assertIn("m8-l1-ghost-image", diagram_ids)
                templates = {
                    asset["meta"]["template"]
                    for asset in lesson["generated_assets"]["diagrams"]
                }
                self.assertEqual(templates, {"optics_ray_diagram"})
            if lesson["lesson_id"] == "M8_L5":
                diagram_ids = {asset["asset_id"] for asset in lesson["generated_assets"]["diagrams"]}
                self.assertEqual(diagram_ids, {"m8-l5-critical-angle", "m8-l5-optical-fiber"})
                templates = {
                    asset["meta"]["template"]
                    for asset in lesson["generated_assets"]["diagrams"]
                }
                self.assertEqual(templates, {"wave_diagram"})
            if lesson["lesson_id"] == "M8_L6":
                diagram_ids = {asset["asset_id"] for asset in lesson["generated_assets"]["diagrams"]}
                self.assertEqual(diagram_ids, {"m8-l6-plane-mirror-ghost", "m8-l6-converging-real", "m8-l6-diverging-ghost"})
                templates = {
                    asset["meta"]["template"]
                    for asset in lesson["generated_assets"]["diagrams"]
                }
                self.assertEqual(templates, {"optics_ray_diagram"})

            for example in contract["worked_examples"]:
                self.assertTrue(example["answer_reason"])

            skill_tags = set()
            for question in [*diagnostic_items, *concept_checks, *transfer_items]:
                if question["type"] == "short":
                    accepted = question.get("accepted_answers") or []
                    if accepted and not all(str(answer).strip().isdigit() for answer in accepted) and question.get("acceptance_rules"):
                        self.assertIn("phrase_groups", question.get("acceptance_rules", {}))
                self.assertTrue(question.get("skill_tags"))
                skill_tags.update(question.get("skill_tags") or [])
            self.assertGreaterEqual(len(skill_tags), 3)

        self.assertEqual(len(simulation_concepts), 6)
        self.assertEqual(len(focus_prompts), 6)

    def test_m8_curriculum_scope_stays_on_light(self) -> None:
        mastery_text = " ".join(M8_MODULE_DOC.get("mastery_outcomes") or []).lower()
        description_text = str(M8_MODULE_DOC.get("description") or "").lower()
        self.assertIn("reflection", description_text)
        self.assertIn("refraction", description_text)
        self.assertIn("critical angle", description_text)
        self.assertIn("total internal reflection", description_text)
        self.assertIn("ray diagrams", description_text)
        self.assertIn("reflection", mastery_text)
        self.assertIn("refraction", mastery_text)
        self.assertIn("critical angle", mastery_text)
        self.assertIn("total internal reflection", mastery_text)
        self.assertIn("ray diagrams", mastery_text)
        self.assertNotIn("current", mastery_text)
        self.assertNotIn("momentum", mastery_text)

    def test_m8_l6_route_sketch_keeps_line_roles_and_image_types_explicit(self) -> None:
        lesson = next(payload for lesson_id, payload in M8_LESSONS if lesson_id == "M8_L6")
        contract = lesson["authoring_contract"]
        simulation_contract = contract["simulation_contract"]
        mastery_prompts = " ".join(str(item.get("prompt") or "") for item in lesson["phases"]["transfer"]["items"]).lower()
        reflection_text = " ".join(contract.get("reflection_prompts") or []).lower()

        self.assertEqual(simulation_contract["concept"], "ray_diagram")
        self.assertIn("guide lines", simulation_contract["focus_prompt"].lower())
        self.assertIn("ghost meeting points", simulation_contract["focus_prompt"].lower())
        self.assertIn("backward extensions", simulation_contract["takeaway"].lower())
        self.assertIn("screen", reflection_text)
        self.assertIn("plane mirror", mastery_prompts)
        self.assertIn("converging lens", mastery_prompts)
        self.assertIn("diverging-lens", mastery_prompts)

    def test_m9_bundle_uses_v3_contract_and_generated_assets(self) -> None:
        self.assertEqual(M9_MODULE_DOC["id"], "M9")
        self.assertEqual(M9_MODULE_DOC["title"], "Sound")
        self.assertEqual(M9_MODULE_DOC["authoring_standard"], "lesson_authoring_spec_v3")
        self.assertEqual(len(M9_LESSONS), 6)
        self.assertEqual(len(M9_SIM_LABS), 6)
        self.assertEqual(
            [lesson_id for lesson_id, _ in M9_LESSONS],
            ["M9_L1", "M9_L2", "M9_L3", "M9_L4", "M9_L5", "M9_L6"],
        )

        simulation_concepts = set()
        focus_prompts = set()
        for _, lesson in M9_LESSONS:
            contract = lesson["authoring_contract"]
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            transfer_items = lesson["phases"]["transfer"]["items"]
            simulation_contract = contract["simulation_contract"]
            self.assertEqual(
                contract["assessment_bank_targets"],
                {
                    "diagnostic_pool_min": 10,
                    "concept_gate_pool_min": 8,
                    "mastery_pool_min": 10,
                    "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery on every fresh attempt before repeating any previous stem.",
                },
            )
            self.assertGreaterEqual(len(diagnostic_items), 10)
            self.assertGreaterEqual(len(concept_checks), 8)
            self.assertGreaterEqual(len(transfer_items), 10)
            self.assertEqual(len(contract["visual_assets"]), 1)
            self.assertEqual(len(contract["animation_assets"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["diagrams"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["animations"]), 1)
            self.assertIn("generated_lab", lesson["phases"]["simulation_inquiry"])
            self.assertGreaterEqual(len(contract["worked_examples"]), 3)
            self.assertGreaterEqual(len(contract["core_concepts"]), 4)
            self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 3)
            self.assertTrue(simulation_contract["asset_id"])
            self.assertTrue(simulation_contract["concept"])
            self.assertTrue(simulation_contract["focus_prompt"])
            simulation_concepts.add(simulation_contract["concept"])
            focus_prompts.add(simulation_contract["focus_prompt"])

            scaffold_support = contract["scaffold_support"]
            self.assertTrue(scaffold_support["core_idea"])
            self.assertTrue(scaffold_support["reasoning"])
            self.assertTrue(scaffold_support["common_trap"])
            self.assertGreaterEqual(len(scaffold_support["extra_sections"]), 2)

            for example in contract["worked_examples"]:
                self.assertTrue(example["answer_reason"])

            skill_tags = set()
            for question in [*diagnostic_items, *concept_checks, *transfer_items]:
                if question["type"] == "short":
                    accepted = question.get("accepted_answers") or []
                    if accepted and not all(str(answer).strip().isdigit() for answer in accepted) and question.get("acceptance_rules"):
                        self.assertIn("phrase_groups", question.get("acceptance_rules", {}))
                self.assertTrue(question.get("skill_tags"))
                skill_tags.update(question.get("skill_tags") or [])
            self.assertGreaterEqual(len(skill_tags), 4)

        self.assertEqual(len(simulation_concepts), 6)
        self.assertEqual(len(focus_prompts), 6)

    def test_m9_curriculum_scope_stays_on_sound(self) -> None:
        mastery_text = " ".join(M9_MODULE_DOC.get("mastery_outcomes") or []).lower()
        description_text = str(M9_MODULE_DOC.get("description") or "").lower()
        self.assertIn("sound production", description_text)
        self.assertIn("compressions", description_text)
        self.assertIn("frequency", description_text)
        self.assertIn("pitch", description_text)
        self.assertIn("ultrasound", description_text)
        self.assertIn("pitch", mastery_text)
        self.assertIn("ultrasound", mastery_text)
        self.assertIn("doppler", mastery_text)
        self.assertNotIn("current", mastery_text)
        self.assertNotIn("mirror", mastery_text)
        self.assertNotIn("latent heat", mastery_text)

    def test_m9_l5_and_l6_keep_echo_depth_and_doppler_flow_explicit(self) -> None:
        echo_lesson = next(payload for lesson_id, payload in M9_LESSONS if lesson_id == "M9_L5")
        doppler_lesson = next(payload for lesson_id, payload in M9_LESSONS if lesson_id == "M9_L6")
        echo_contract = echo_lesson["authoring_contract"]
        doppler_contract = doppler_lesson["authoring_contract"]
        echo_mastery = " ".join(str(item.get("prompt") or "") for item in echo_lesson["phases"]["transfer"]["items"]).lower()
        doppler_mastery = " ".join(str(item.get("prompt") or "") for item in doppler_lesson["phases"]["transfer"]["items"]).lower()

        self.assertEqual(echo_contract["simulation_contract"]["concept"], "echo_imaging")
        self.assertIn("divide by two", echo_contract["simulation_contract"]["takeaway"].lower())
        self.assertIn("many echoes", " ".join(echo_contract["reflection_prompts"]).lower())
        self.assertIn("return time", echo_mastery)
        self.assertIn("doppler", " ".join(doppler_contract["reflection_prompts"]).lower())
        self.assertIn("higher returned frequency", doppler_mastery)
        self.assertIn("moving away", doppler_mastery)

    def test_m10_bundle_uses_v3_contract_and_generated_assets(self) -> None:
        self.assertEqual(M10_MODULE_DOC["id"], "M10")
        self.assertEqual(M10_MODULE_DOC["title"], "Electrical Quantities")
        self.assertEqual(M10_MODULE_DOC["authoring_standard"], "lesson_authoring_spec_v3")
        self.assertEqual(len(M10_LESSONS), 6)
        self.assertEqual(len(M10_SIM_LABS), 6)
        self.assertEqual(
            [lesson_id for lesson_id, _ in M10_LESSONS],
            ["M10_L1", "M10_L2", "M10_L3", "M10_L4", "M10_L5", "M10_L6"],
        )

        simulation_concepts = set()
        focus_prompts = set()
        for _, lesson in M10_LESSONS:
            contract = lesson["authoring_contract"]
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            transfer_items = lesson["phases"]["transfer"]["items"]
            simulation_contract = contract["simulation_contract"]
            self.assertEqual(
                contract["assessment_bank_targets"],
                {
                    "diagnostic_pool_min": 8,
                    "concept_gate_pool_min": 6,
                    "mastery_pool_min": 8,
                    "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
                },
            )
            self.assertGreaterEqual(len(diagnostic_items), 8)
            self.assertGreaterEqual(len(concept_checks), 6)
            self.assertGreaterEqual(len(transfer_items), 8)
            self.assertEqual(len(contract["visual_assets"]), 1)
            self.assertEqual(len(contract["animation_assets"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["diagrams"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["animations"]), 1)
            self.assertIn("generated_lab", lesson["phases"]["simulation_inquiry"])
            self.assertGreaterEqual(len(contract["worked_examples"]), 3)
            self.assertGreaterEqual(len(contract["core_concepts"]), 4)
            self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 3)
            self.assertTrue(simulation_contract["asset_id"])
            self.assertTrue(simulation_contract["concept"])
            self.assertTrue(simulation_contract["focus_prompt"])
            self.assertTrue(simulation_contract["baseline_case"])
            self.assertGreaterEqual(len(simulation_contract["controls"]), 3)
            self.assertGreaterEqual(len(simulation_contract["readouts"]), 3)
            self.assertGreaterEqual(len(simulation_contract["comparison_tasks"]), 2)
            simulation_concepts.add(simulation_contract["concept"])
            focus_prompts.add(simulation_contract["focus_prompt"])

            scaffold_support = contract["scaffold_support"]
            self.assertTrue(scaffold_support["core_idea"])
            self.assertTrue(scaffold_support["reasoning"])
            self.assertTrue(scaffold_support["common_trap"])
            self.assertGreaterEqual(len(scaffold_support["extra_sections"]), 2)

            for example in contract["worked_examples"]:
                self.assertTrue(example["answer_reason"])

            skill_tags = set()
            for question in [*diagnostic_items, *concept_checks, *transfer_items]:
                if question["type"] == "short":
                    accepted = question.get("accepted_answers") or []
                    if accepted and not all(str(answer).strip().isdigit() for answer in accepted) and question.get("acceptance_rules"):
                        self.assertIn("phrase_groups", question.get("acceptance_rules", {}))
                self.assertTrue(question.get("skill_tags"))
                skill_tags.update(question.get("skill_tags") or [])
            self.assertGreaterEqual(len(skill_tags), 4)

        self.assertEqual(len(simulation_concepts), 6)
        self.assertEqual(len(focus_prompts), 6)

    def test_m10_curriculum_scope_stays_on_electrical_quantities(self) -> None:
        mastery_text = " ".join(M10_MODULE_DOC.get("mastery_outcomes") or []).lower()
        description_text = str(M10_MODULE_DOC.get("description") or "").lower()
        self.assertIn("charge", mastery_text)
        self.assertIn("current", mastery_text)
        self.assertIn("voltage", mastery_text)
        self.assertIn("resistance", mastery_text)
        self.assertIn("ohm", mastery_text)
        self.assertIn("flow-grid 2.0", description_text)
        self.assertIn("carrier-loop", description_text)
        self.assertNotIn("pressure", mastery_text)
        self.assertNotIn("brownian", mastery_text)
        self.assertNotIn("reflection", mastery_text)
        self.assertNotIn("ultrasound", mastery_text)

    def test_m11_bundle_uses_v3_contract_and_generated_assets(self) -> None:
        self.assertEqual(M11_MODULE_DOC["id"], "M11")
        self.assertEqual(M11_MODULE_DOC["title"], "Circuits")
        self.assertEqual(M11_MODULE_DOC["authoring_standard"], "lesson_authoring_spec_v3")
        self.assertEqual(len(M11_LESSONS), 6)
        self.assertEqual(len(M11_SIM_LABS), 6)
        self.assertEqual(
            [lesson_id for lesson_id, _ in M11_LESSONS],
            ["M11_L1", "M11_L2", "M11_L3", "M11_L4", "M11_L5", "M11_L6"],
        )

        simulation_concepts = set()
        focus_prompts = set()
        for _, lesson in M11_LESSONS:
            contract = lesson["authoring_contract"]
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            transfer_items = lesson["phases"]["transfer"]["items"]
            simulation_contract = contract["simulation_contract"]

            self.assertEqual(
                contract["assessment_bank_targets"],
                {
                    "diagnostic_pool_min": 10,
                    "concept_gate_pool_min": 8,
                    "mastery_pool_min": 10,
                    "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery on every fresh attempt before repeating any previous stem.",
                },
            )
            self.assertGreaterEqual(len(diagnostic_items), 10)
            self.assertGreaterEqual(len(concept_checks), 8)
            self.assertGreaterEqual(len(transfer_items), 10)
            self.assertEqual(len(contract["visual_assets"]), 1)
            self.assertEqual(len(contract["animation_assets"]), 1)
            self.assertGreaterEqual(len(contract["worked_examples"]), 3)
            self.assertGreaterEqual(len(contract["core_concepts"]), 4)
            self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 5)
            self.assertTrue(simulation_contract["asset_id"])
            self.assertTrue(simulation_contract["concept"])
            self.assertTrue(simulation_contract["focus_prompt"])
            self.assertGreaterEqual(len(simulation_contract["controls"]), 3)
            self.assertGreaterEqual(len(simulation_contract["readouts"]), 3)
            simulation_concepts.add(simulation_contract["concept"])
            focus_prompts.add(simulation_contract["focus_prompt"])

            skill_tags = set()
            for question in [*diagnostic_items, *concept_checks, *transfer_items]:
                if question["type"] == "short":
                    accepted = question.get("accepted_answers") or []
                    if accepted and not all(str(answer).strip().isdigit() for answer in accepted):
                        self.assertIn("phrase_groups", question.get("acceptance_rules", {}))
                self.assertTrue(question.get("skill_tags"))
                skill_tags.update(question.get("skill_tags") or [])
            self.assertGreaterEqual(len(skill_tags), 4)

        self.assertEqual(len(simulation_concepts), 6)
        self.assertEqual(len(focus_prompts), 6)

    def test_m11_curriculum_scope_stays_on_circuit_networks(self) -> None:
        mastery_text = " ".join(M11_MODULE_DOC.get("mastery_outcomes") or []).lower()
        description_text = str(M11_MODULE_DOC.get("description") or "").lower()
        self.assertIn("series", mastery_text)
        self.assertIn("parallel", mastery_text)
        self.assertIn("power", mastery_text)
        self.assertIn("circuit diagram", mastery_text)
        self.assertIn("combined resistance", mastery_text)
        self.assertIn("switchyard-loop", description_text)
        self.assertNotIn("brownian", mastery_text)
        self.assertNotIn("pressure", mastery_text)
        self.assertNotIn("ultrasound", mastery_text)

    def test_m12_bundle_uses_v3_contract_and_generated_assets(self) -> None:
        self.assertEqual(M12_MODULE_DOC["id"], "M12")
        self.assertEqual(M12_MODULE_DOC["title"], "Magnetism & Electromagnetic Effects")
        self.assertEqual(M12_MODULE_DOC["authoring_standard"], "lesson_authoring_spec_v3")
        self.assertEqual(len(M12_LESSONS), 6)
        self.assertEqual(len(M12_SIM_LABS), 6)
        self.assertEqual(
            [lesson_id for lesson_id, _ in M12_LESSONS],
            ["M12_L1", "M12_L2", "M12_L3", "M12_L4", "M12_L5", "M12_L6"],
        )

        simulation_concepts = set()
        focus_prompts = set()
        for _, lesson in M12_LESSONS:
            contract = lesson["authoring_contract"]
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            transfer_items = lesson["phases"]["transfer"]["items"]
            simulation_contract = contract["simulation_contract"]

            self.assertGreaterEqual(len(diagnostic_items), 10)
            self.assertGreaterEqual(len(concept_checks), 8)
            self.assertGreaterEqual(len(transfer_items), 10)
            self.assertEqual(len(contract["visual_assets"]), 1)
            self.assertEqual(len(contract["animation_assets"]), 1)
            self.assertGreaterEqual(len(contract["worked_examples"]), 3)
            self.assertGreaterEqual(len(contract["core_concepts"]), 4)
            self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 3)
            self.assertTrue(simulation_contract["asset_id"])
            self.assertTrue(simulation_contract["concept"])
            self.assertTrue(simulation_contract["focus_prompt"])
            self.assertTrue(simulation_contract["baseline_case"])
            self.assertGreaterEqual(len(simulation_contract["controls"]), 3)
            self.assertGreaterEqual(len(simulation_contract["readouts"]), 3)
            self.assertGreaterEqual(len(simulation_contract["comparison_tasks"]), 2)
            simulation_concepts.add(simulation_contract["concept"])
            focus_prompts.add(simulation_contract["focus_prompt"])

            representation_kinds = {item["kind"] for item in contract["representations"]}
            self.assertIn("words", representation_kinds)
            self.assertIn("formula", representation_kinds)
            self.assertTrue(any(kind in {"diagram", "graph", "table", "model"} for kind in representation_kinds))

            skill_tags = set()
            for question in [*diagnostic_items, *concept_checks, *transfer_items]:
                if question["type"] == "short":
                    accepted = question.get("accepted_answers") or []
                    if accepted and not all(str(answer).strip().isdigit() for answer in accepted):
                        self.assertIn("phrase_groups", question.get("acceptance_rules", {}))
                self.assertTrue(question.get("skill_tags"))
                skill_tags.update(question.get("skill_tags") or [])
            self.assertGreaterEqual(len(skill_tags), 4)

        self.assertEqual(len(simulation_concepts), 6)
        self.assertEqual(len(focus_prompts), 6)

    def test_m12_curriculum_scope_stays_on_field_weave_electromagnetism(self) -> None:
        mastery_text = " ".join(M12_MODULE_DOC.get("mastery_outcomes") or []).lower()
        description_text = str(M12_MODULE_DOC.get("description") or "").lower()
        self.assertIn("magnetic fields", mastery_text)
        self.assertIn("electromagnets", mastery_text)
        self.assertIn("motor effect", mastery_text)
        self.assertIn("induction", mastery_text)
        self.assertIn("transformers", mastery_text)
        self.assertIn("field-weave", description_text)
        self.assertNotIn("ultrasound", mastery_text)
        self.assertNotIn("pressure", mastery_text)

    def test_m13_bundle_uses_v3_contract_and_generated_assets(self) -> None:
        self.assertEqual(M13_MODULE_DOC["id"], "M13")
        self.assertEqual(M13_MODULE_DOC["title"], "Radioactivity")
        self.assertEqual(M13_MODULE_DOC["authoring_standard"], "lesson_authoring_spec_v3")
        self.assertEqual(len(M13_LESSONS), 6)
        self.assertEqual(len(M13_SIM_LABS), 6)
        self.assertEqual(
            [lesson_id for lesson_id, _ in M13_LESSONS],
            ["M13_L1", "M13_L2", "M13_L3", "M13_L4", "M13_L5", "M13_L6"],
        )

        simulation_concepts = set()
        focus_prompts = set()
        for _, lesson in M13_LESSONS:
            contract = lesson["authoring_contract"]
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            transfer_items = lesson["phases"]["transfer"]["items"]
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
            self.assertGreaterEqual(len(transfer_items), 10)
            self.assertEqual(len(contract["visual_assets"]), 1)
            self.assertEqual(len(contract["animation_assets"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["diagrams"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["animations"]), 1)
            self.assertIn("generated_lab", lesson["phases"]["simulation_inquiry"])
            self.assertGreaterEqual(len(contract["worked_examples"]), 3)
            self.assertGreaterEqual(len(contract["core_concepts"]), 4)
            self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 3)
            self.assertTrue(simulation_contract["asset_id"])
            self.assertTrue(simulation_contract["concept"])
            self.assertTrue(simulation_contract["focus_prompt"])
            self.assertTrue(simulation_contract["baseline_case"])
            self.assertGreaterEqual(len(simulation_contract["controls"]), 3)
            self.assertGreaterEqual(len(simulation_contract["readouts"]), 3)
            self.assertGreaterEqual(len(simulation_contract["comparison_tasks"]), 2)
            simulation_concepts.add(simulation_contract["concept"])
            focus_prompts.add(simulation_contract["focus_prompt"])

            representation_kinds = {item["kind"] for item in contract["representations"]}
            self.assertIn("words", representation_kinds)
            self.assertIn("formula", representation_kinds)
            self.assertTrue(any(kind in {"diagram", "graph", "table", "model"} for kind in representation_kinds))

            skill_tags = set()
            for question in [*diagnostic_items, *concept_checks, *transfer_items]:
                if question["type"] == "short":
                    accepted = question.get("accepted_answers") or []
                    if accepted and not all(str(answer).strip().isdigit() for answer in accepted):
                        self.assertIn("phrase_groups", question.get("acceptance_rules", {}))
                self.assertTrue(question.get("skill_tags"))
                skill_tags.update(question.get("skill_tags") or [])
            self.assertGreaterEqual(len(skill_tags), 4)

        self.assertEqual(len(simulation_concepts), 6)
        self.assertEqual(len(focus_prompts), 6)

    def test_m13_half_life_visual_uses_physics_graph_contract(self) -> None:
        lesson = next(payload for lesson_id, payload in M13_LESSONS if lesson_id == "M13_L4")
        visual = lesson["authoring_contract"]["visual_assets"][0]
        self.assertEqual(visual["template"], "physics_graph")
        self.assertEqual(visual["meta"]["graph_type"], "generic_xy")
        self.assertEqual(visual["meta"]["x_label"], "Time (half-life intervals)")
        self.assertEqual(visual["meta"]["y_label"], "Undecayed nuclei")

    def test_m13_curriculum_scope_stays_on_radioactivity(self) -> None:
        mastery_text = " ".join(M13_MODULE_DOC.get("mastery_outcomes") or []).lower()
        description_text = str(M13_MODULE_DOC.get("description") or "").lower()
        self.assertIn("atomic structure", mastery_text)
        self.assertIn("isotopes", mastery_text)
        self.assertIn("alpha", mastery_text)
        self.assertIn("half-life", mastery_text)
        self.assertIn("background radiation", mastery_text)
        self.assertIn("decay equations", mastery_text)
        self.assertIn("core-vault", description_text)
        self.assertNotIn("current", mastery_text)
        self.assertNotIn("lens", mastery_text)
        self.assertNotIn("ultrasound", mastery_text)

    def test_a1_bundle_uses_v3_contract_and_generated_assets(self) -> None:
        self.assertEqual(A1_MODULE_DOC["id"], "A1")
        self.assertEqual(A1_MODULE_DOC["title"], "Matter, Radiation and Particles")
        self.assertEqual(A1_MODULE_DOC["authoring_standard"], "lesson_authoring_spec_v3")
        self.assertEqual(len(A1_LESSONS), 6)
        self.assertEqual(len(A1_SIM_LABS), 6)
        self.assertEqual(
            [lesson_id for lesson_id, _ in A1_LESSONS],
            ["A1_L1", "A1_L2", "A1_L3", "A1_L4", "A1_L5", "A1_L6"],
        )

        simulation_concepts = set()
        focus_prompts = set()
        for _, lesson in A1_LESSONS:
            contract = lesson["authoring_contract"]
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            transfer_items = lesson["phases"]["transfer"]["items"]
            simulation_contract = contract["simulation_contract"]

            self.assertEqual(
                contract["assessment_bank_targets"],
                {
                    "diagnostic_pool_min": 6,
                    "concept_gate_pool_min": 4,
                    "mastery_pool_min": 6,
                    "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
                },
            )
            self.assertGreaterEqual(len(diagnostic_items), 6)
            self.assertGreaterEqual(len(concept_checks), 4)
            self.assertGreaterEqual(len(transfer_items), 6)
            self.assertEqual(len(contract["visual_assets"]), 1)
            self.assertEqual(len(contract["animation_assets"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["diagrams"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["animations"]), 1)
            self.assertIn("generated_lab", lesson["phases"]["simulation_inquiry"])
            self.assertGreaterEqual(len(contract["worked_examples"]), 3)
            self.assertGreaterEqual(len(contract["core_concepts"]), 4)
            self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 3)
            self.assertTrue(simulation_contract["asset_id"])
            self.assertTrue(simulation_contract["concept"])
            self.assertTrue(simulation_contract["focus_prompt"])
            self.assertTrue(simulation_contract["baseline_case"])
            self.assertGreaterEqual(len(simulation_contract["controls"]), 3)
            self.assertGreaterEqual(len(simulation_contract["readouts"]), 3)
            self.assertGreaterEqual(len(simulation_contract["comparison_tasks"]), 2)
            simulation_concepts.add(simulation_contract["concept"])
            focus_prompts.add(simulation_contract["focus_prompt"])

            representation_kinds = {item["kind"] for item in contract["representations"]}
            self.assertIn("words", representation_kinds)
            self.assertIn("formula", representation_kinds)
            self.assertTrue(any(kind in {"diagram", "graph", "table", "model"} for kind in representation_kinds))

            skill_tags = set()
            for question in [*diagnostic_items, *concept_checks, *transfer_items]:
                if question["type"] == "short":
                    accepted = question.get("accepted_answers") or []
                    if accepted and not all(str(answer).strip().isdigit() for answer in accepted):
                        self.assertIn("phrase_groups", question.get("acceptance_rules", {}))
                self.assertTrue(question.get("skill_tags"))
                skill_tags.update(question.get("skill_tags") or [])
            self.assertGreaterEqual(len(skill_tags), 4)

        self.assertEqual(len(simulation_concepts), 6)
        self.assertEqual(len(focus_prompts), 6)

    def test_a1_curriculum_scope_stays_on_matter_radiation_and_particles(self) -> None:
        mastery_text = " ".join(A1_MODULE_DOC.get("mastery_outcomes") or []).lower()
        description_text = str(A1_MODULE_DOC.get("description") or "").lower()
        self.assertIn("subatomic structure", mastery_text)
        self.assertIn("hadrons", mastery_text)
        self.assertIn("antiparticles", mastery_text)
        self.assertIn("conservation", mastery_text)
        self.assertIn("travelers and bundles", description_text)
        self.assertNotIn("ultrasound", mastery_text)
        self.assertNotIn("radioactivity", mastery_text)
        self.assertNotIn("current", mastery_text)

    def test_a1_lessons_balance_conceptual_and_quantitative_reasoning(self) -> None:
        quantitative_tokens = ("charge", "quark", "baryon", "lepton", "photon", "energy", "mev", "conservation", "number")
        explanation_tokens = ("why", "explain", "describe", "which statement", "best summary", "correction")

        for lesson_id, lesson in A1_LESSONS:
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            mastery_items = lesson["phases"]["transfer"]["items"]
            all_items = [*diagnostic_items, *concept_checks, *mastery_items]
            prompts = [str(item.get("prompt") or "").lower() for item in all_items]

            short_count = sum(1 for item in all_items if item.get("type") == "short")
            quantitative_count = sum(1 for prompt in prompts if any(token in prompt for token in quantitative_tokens) or any(ch.isdigit() for ch in prompt))
            explanation_count = sum(1 for prompt in prompts if any(token in prompt for token in explanation_tokens))
            mastery_short_count = sum(1 for item in mastery_items if item.get("type") == "short")

            self.assertGreaterEqual(short_count, 2, lesson_id)
            self.assertGreaterEqual(quantitative_count, 3, lesson_id)
            self.assertGreaterEqual(explanation_count, 3, lesson_id)
            self.assertGreaterEqual(mastery_short_count, 1, lesson_id)

    def test_a2_bundle_uses_v3_contract_and_generated_assets(self) -> None:
        self.assertEqual(A2_MODULE_DOC["id"], "A2")
        self.assertEqual(A2_MODULE_DOC["title"], "Quantum Phenomena and Atomic Spectra")
        self.assertEqual(A2_MODULE_DOC["authoring_standard"], "lesson_authoring_spec_v3")
        self.assertEqual(len(A2_LESSONS), 6)
        self.assertEqual(len(A2_SIM_LABS), 6)
        self.assertEqual(
            [lesson_id for lesson_id, _ in A2_LESSONS],
            ["A2_L1", "A2_L2", "A2_L3", "A2_L4", "A2_L5", "A2_L6"],
        )

        simulation_concepts = set()
        focus_prompts = set()
        for _, lesson in A2_LESSONS:
            contract = lesson["authoring_contract"]
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            transfer_items = lesson["phases"]["transfer"]["items"]
            simulation_contract = contract["simulation_contract"]

            self.assertEqual(
                contract["assessment_bank_targets"],
                {
                    "diagnostic_pool_min": 6,
                    "concept_gate_pool_min": 4,
                    "mastery_pool_min": 6,
                    "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
                },
            )
            self.assertGreaterEqual(len(diagnostic_items), 6)
            self.assertGreaterEqual(len(concept_checks), 4)
            self.assertGreaterEqual(len(transfer_items), 6)
            self.assertEqual(len(contract["visual_assets"]), 1)
            self.assertEqual(len(contract["animation_assets"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["diagrams"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["animations"]), 1)
            self.assertIn("generated_lab", lesson["phases"]["simulation_inquiry"])
            self.assertGreaterEqual(len(contract["worked_examples"]), 3)
            self.assertGreaterEqual(len(contract["core_concepts"]), 4)
            self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 3)
            self.assertTrue(simulation_contract["asset_id"])
            self.assertTrue(simulation_contract["concept"])
            self.assertTrue(simulation_contract["focus_prompt"])
            self.assertTrue(simulation_contract["baseline_case"])
            self.assertGreaterEqual(len(simulation_contract["controls"]), 3)
            self.assertGreaterEqual(len(simulation_contract["readouts"]), 3)
            self.assertGreaterEqual(len(simulation_contract["comparison_tasks"]), 2)
            simulation_concepts.add(simulation_contract["concept"])
            focus_prompts.add(simulation_contract["focus_prompt"])

            representation_kinds = {item["kind"] for item in contract["representations"]}
            self.assertIn("words", representation_kinds)
            self.assertIn("formula", representation_kinds)
            self.assertTrue(any(kind in {"diagram", "graph", "table", "model"} for kind in representation_kinds))

            skill_tags = set()
            for question in [*diagnostic_items, *concept_checks, *transfer_items]:
                if question["type"] == "short":
                    accepted = question.get("accepted_answers") or []
                    if accepted and not all(str(answer).strip().isdigit() for answer in accepted):
                        self.assertIn("phrase_groups", question.get("acceptance_rules", {}))
                self.assertTrue(question.get("skill_tags"))
                skill_tags.update(question.get("skill_tags") or [])
            self.assertGreaterEqual(len(skill_tags), 4)

        self.assertEqual(len(simulation_concepts), 6)
        self.assertEqual(len(focus_prompts), 6)

    def test_a2_curriculum_scope_stays_on_quantum_phenomena_and_atomic_spectra(self) -> None:
        mastery_text = " ".join(A2_MODULE_DOC.get("mastery_outcomes") or []).lower()
        description_text = str(A2_MODULE_DOC.get("description") or "").lower()
        self.assertIn("quantized energy levels", mastery_text)
        self.assertIn("spectra", mastery_text)
        self.assertIn("photoelectric", mastery_text)
        self.assertIn("de broglie", mastery_text)
        self.assertIn("energy floors", description_text)
        self.assertNotIn("projectile", mastery_text)
        self.assertNotIn("ultrasound", mastery_text)
        self.assertNotIn("radioactivity", mastery_text)

    def test_a2_lessons_balance_conceptual_and_quantitative_reasoning(self) -> None:
        quantitative_tokens = ("j", "ev", "hz", "threshold", "frequency", "work function", "lambda", "momentum", "spectrum")
        explanation_tokens = ("why", "explain", "describe", "which statement", "best summary", "correction")

        for lesson_id, lesson in A2_LESSONS:
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            mastery_items = lesson["phases"]["transfer"]["items"]
            all_items = [*diagnostic_items, *concept_checks, *mastery_items]
            prompts = [str(item.get("prompt") or "").lower() for item in all_items]

            short_count = sum(1 for item in all_items if item.get("type") == "short")
            quantitative_count = sum(1 for prompt in prompts if any(token in prompt for token in quantitative_tokens) or any(ch.isdigit() for ch in prompt))
            explanation_count = sum(1 for prompt in prompts if any(token in prompt for token in explanation_tokens))
            mastery_short_count = sum(1 for item in mastery_items if item.get("type") == "short")

            self.assertGreaterEqual(short_count, 2, lesson_id)
            self.assertGreaterEqual(quantitative_count, 3, lesson_id)
            self.assertGreaterEqual(explanation_count, 3, lesson_id)
            self.assertGreaterEqual(mastery_short_count, 1, lesson_id)

    def test_a3_bundle_uses_v3_contract_and_generated_assets(self) -> None:
        self.assertEqual(A3_MODULE_DOC["id"], "A3")
        self.assertEqual(A3_MODULE_DOC["title"], "Advanced Waves and Optics")
        self.assertEqual(A3_MODULE_DOC["authoring_standard"], "lesson_authoring_spec_v3")
        self.assertEqual(len(A3_LESSONS), 6)
        self.assertEqual(len(A3_SIM_LABS), 6)
        self.assertEqual(
            [lesson_id for lesson_id, _ in A3_LESSONS],
            ["A3_L1", "A3_L2", "A3_L3", "A3_L4", "A3_L5", "A3_L6"],
        )

        simulation_concepts = set()
        focus_prompts = set()
        for _, lesson in A3_LESSONS:
            contract = lesson["authoring_contract"]
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            transfer_items = lesson["phases"]["transfer"]["items"]
            simulation_contract = contract["simulation_contract"]

            self.assertEqual(
                contract["assessment_bank_targets"],
                {
                    "diagnostic_pool_min": 6,
                    "concept_gate_pool_min": 4,
                    "mastery_pool_min": 6,
                    "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
                },
            )
            self.assertGreaterEqual(len(diagnostic_items), 6)
            self.assertGreaterEqual(len(concept_checks), 4)
            self.assertGreaterEqual(len(transfer_items), 6)
            self.assertEqual(len(contract["visual_assets"]), 1)
            self.assertEqual(len(contract["animation_assets"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["diagrams"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["animations"]), 1)
            self.assertIn("generated_lab", lesson["phases"]["simulation_inquiry"])
            self.assertGreaterEqual(len(contract["worked_examples"]), 2)
            self.assertGreaterEqual(len(contract["core_concepts"]), 4)
            self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 3)
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
            self.assertTrue(any(kind in {"diagram", "graph", "table", "model", "equation_story"} for kind in representation_kinds))

            skill_tags = set()
            for question in [*diagnostic_items, *concept_checks, *transfer_items]:
                if question["type"] == "short":
                    accepted = question.get("accepted_answers") or []
                    if accepted and not all(str(answer).strip().isdigit() for answer in accepted):
                        self.assertIn("phrase_groups", question.get("acceptance_rules", {}))
                self.assertTrue(question.get("skill_tags"))
                skill_tags.update(question.get("skill_tags") or [])
            self.assertGreaterEqual(len(skill_tags), 4)

        self.assertEqual(len(simulation_concepts), 6)
        self.assertEqual(len(focus_prompts), 6)

    def test_a3_curriculum_scope_stays_on_advanced_waves_and_optics(self) -> None:
        mastery_text = " ".join(A3_MODULE_DOC.get("mastery_outcomes") or []).lower()
        description_text = str(A3_MODULE_DOC.get("description") or "").lower()
        self.assertIn("stationary", mastery_text)
        self.assertIn("interference", mastery_text)
        self.assertIn("diffraction", mastery_text)
        self.assertIn("total internal reflection", mastery_text)
        self.assertIn("wave paths", description_text)
        self.assertNotIn("projectile", mastery_text)
        self.assertNotIn("radioactivity", mastery_text)
        self.assertNotIn("ultrasound", mastery_text)

    def test_a3_lessons_balance_conceptual_and_quantitative_reasoning(self) -> None:
        quantitative_tokens = ("wavelength", "frequency", "period", "theta", "angle", "grating", "phase", "path difference", "critical angle")
        explanation_tokens = ("why", "explain", "describe", "which statement", "best summary", "correction")

        for lesson_id, lesson in A3_LESSONS:
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            mastery_items = lesson["phases"]["transfer"]["items"]
            all_items = [*diagnostic_items, *concept_checks, *mastery_items]
            prompts = [str(item.get("prompt") or "").lower() for item in all_items]

            short_count = sum(1 for item in all_items if item.get("type") == "short")
            quantitative_count = sum(1 for prompt in prompts if any(token in prompt for token in quantitative_tokens) or any(ch.isdigit() for ch in prompt))
            explanation_count = sum(1 for prompt in prompts if any(token in prompt for token in explanation_tokens))
            mastery_short_count = sum(1 for item in mastery_items if item.get("type") == "short")

            self.assertGreaterEqual(short_count, 2, lesson_id)
            self.assertGreaterEqual(quantitative_count, 3, lesson_id)
            self.assertGreaterEqual(explanation_count, 3, lesson_id)
            self.assertGreaterEqual(mastery_short_count, 1, lesson_id)

    def test_f1_bundle_uses_lesson_owned_banks_and_generated_assets(self) -> None:
        self.assertEqual(F1_MODULE_DOC["id"], "F1")
        self.assertEqual(F1_MODULE_DOC["title"], "Scientific Measurement and Representation")
        self.assertEqual(len(F1_LESSONS), 6)
        self.assertEqual(len(F1_SIM_LABS), 6)
        self.assertEqual(
            [lesson_id for lesson_id, _ in F1_LESSONS],
            ["F1_L1", "F1_L2", "F1_L3", "F1_L4", "F1_L5", "F1_L6"],
        )

        for _, lesson in F1_LESSONS:
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            transfer_items = lesson["phases"]["transfer"]["items"]
            self.assertGreaterEqual(len(diagnostic_items), 6)
            self.assertGreaterEqual(len(concept_checks), 5)
            self.assertGreaterEqual(len(transfer_items), 8)
            self.assertEqual(len(lesson["generated_assets"]["diagrams"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["animations"]), 1)
            self.assertIn("generated_lab", lesson["phases"]["simulation_inquiry"])

    def test_f1_curriculum_scope_stays_on_measurement_foundations(self) -> None:
        mastery_text = " ".join(F1_MODULE_DOC.get("mastery_outcomes") or []).lower()
        self.assertIn("si units", mastery_text)
        self.assertIn("scalar and vector", mastery_text)
        self.assertIn("density", mastery_text)
        self.assertIn("uncertainty", mastery_text)
        self.assertNotIn("current", mastery_text)
        self.assertNotIn("series circuit", mastery_text)

    def test_f4_iv_visual_uses_physics_graph_contract(self) -> None:
        self.assertEqual(F4_MODULE_DOC["id"], "F4")
        self.assertEqual(len(F4_LESSONS), 6)
        self.assertEqual(len(F4_SIM_LABS), 6)

        lesson = next(payload for lesson_id, payload in F4_LESSONS if lesson_id == "F4_L3")
        visual = lesson["authoring_contract"]["visual_assets"][0]
        self.assertEqual(visual["template"], "physics_graph")
        self.assertEqual(visual["meta"]["graph_type"], "generic_xy")
        self.assertEqual(visual["meta"]["x_label"], "Voltage (V)")
        self.assertEqual(visual["meta"]["y_label"], "Current (A)")

    def test_m1_bundle_uses_lesson_owned_banks_and_generated_assets(self) -> None:
        self.assertEqual(M1_MODULE_DOC["id"], "M1")
        self.assertEqual(M1_MODULE_DOC["title"], "Motion and Kinematics")
        self.assertEqual(len(M1_LESSONS), 6)
        self.assertEqual(len(M1_SIM_LABS), 6)
        self.assertEqual(
            [lesson_id for lesson_id, _ in M1_LESSONS],
            ["M1_L1", "M1_L2", "M1_L3", "M1_L4", "M1_L5", "M1_L6"],
        )

        for _, lesson in M1_LESSONS:
            contract = lesson["authoring_contract"]
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            transfer_items = lesson["phases"]["transfer"]["items"]
            simulation_contract = contract["simulation_contract"]
            self.assertEqual(
                contract["assessment_bank_targets"],
                {
                    "diagnostic_pool_min": 7,
                    "concept_gate_pool_min": 5,
                    "mastery_pool_min": 10,
                    "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
                },
            )
            self.assertGreaterEqual(len(diagnostic_items), 7)
            self.assertGreaterEqual(len(concept_checks), 5)
            self.assertGreaterEqual(len(transfer_items), 10)
            self.assertGreaterEqual(len(contract["visual_assets"]), 1)
            self.assertEqual(len(contract["animation_assets"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["diagrams"]), len(contract["visual_assets"]))
            self.assertEqual(len(lesson["generated_assets"]["animations"]), 1)
            self.assertIn("generated_lab", lesson["phases"]["simulation_inquiry"])
            self.assertGreaterEqual(len(contract["core_concepts"]), 4)
            self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 3)
            self.assertTrue(simulation_contract["asset_id"])
            self.assertTrue(simulation_contract["concept"])
            self.assertTrue(simulation_contract["focus_prompt"])
            self.assertTrue(simulation_contract["baseline_case"])
            self.assertGreaterEqual(len(simulation_contract["controls"]), 3)
            self.assertGreaterEqual(len(simulation_contract["readouts"]), 3)
            self.assertGreaterEqual(len(simulation_contract["comparison_tasks"]), 2)

            skill_tags = set()
            for question in [*diagnostic_items, *concept_checks, *transfer_items]:
                if question["type"] == "short":
                    accepted = question.get("accepted_answers") or []
                    if accepted and not all(str(answer).strip().isdigit() for answer in accepted) and question.get("acceptance_rules"):
                        self.assertIn("phrase_groups", question.get("acceptance_rules", {}))
                self.assertTrue(question.get("skill_tags"))
                skill_tags.update(question.get("skill_tags") or [])
            self.assertGreaterEqual(len(skill_tags), 4)

    def test_m1_graph_lessons_use_physics_graph_assets(self) -> None:
        expected_visual_counts = {
            "M1_L1": 2,
            "M1_L2": 1,
            "M1_L3": 1,
            "M1_L4": 1,
            "M1_L5": 2,
            "M1_L6": 1,
        }

        for lesson_id, lesson in M1_LESSONS:
            visuals = lesson["authoring_contract"]["visual_assets"]
            self.assertEqual(len(visuals), expected_visual_counts[lesson_id])
            for visual in visuals:
                self.assertEqual(visual["template"], "physics_graph")
                self.assertIn(visual["meta"]["graph_type"], {"generic_xy", "kinematics_time_series"})

        lesson_l6 = next(payload for lesson_id, payload in M1_LESSONS if lesson_id == "M1_L6")
        self.assertTrue(lesson_l6["authoring_contract"]["visual_assets"][0]["meta"]["fill_under_series"])

    def test_m1_curriculum_scope_stays_graph_and_kinematics_focused(self) -> None:
        mastery_text = " ".join(M1_MODULE_DOC.get("mastery_outcomes") or []).lower()
        self.assertIn("distance-time", mastery_text)
        self.assertIn("speed-time", mastery_text)
        self.assertIn("acceleration", mastery_text)
        self.assertIn("constant-acceleration", mastery_text)
        self.assertIn("area", mastery_text)
        self.assertNotIn("density", mastery_text)
        self.assertNotIn("series circuit", mastery_text)

    def test_m2_bundle_uses_lesson_owned_banks_and_generated_assets(self) -> None:
        self.assertEqual(M2_MODULE_DOC["id"], "M2")
        self.assertEqual(M2_MODULE_DOC["title"], "Forces and Equilibrium")
        self.assertEqual(len(M2_LESSONS), 6)
        self.assertEqual(len(M2_SIM_LABS), 6)
        self.assertEqual(
            [lesson_id for lesson_id, _ in M2_LESSONS],
            ["M2_L1", "M2_L2", "M2_L3", "M2_L4", "M2_L5", "M2_L6"],
        )

        for _, lesson in M2_LESSONS:
            contract = lesson["authoring_contract"]
            diagnostic_items = lesson["phases"]["diagnostic"]["items"]
            concept_checks = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
            transfer_items = lesson["phases"]["transfer"]["items"]
            simulation_contract = contract["simulation_contract"]
            self.assertEqual(
                contract["assessment_bank_targets"],
                {
                    "diagnostic_pool_min": 6,
                    "concept_gate_pool_min": 4,
                    "mastery_pool_min": 8,
                    "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
                },
            )
            self.assertGreaterEqual(len(diagnostic_items), 6)
            self.assertGreaterEqual(len(concept_checks), 4)
            self.assertGreaterEqual(len(transfer_items), 8)
            self.assertEqual(len(contract["visual_assets"]), 1)
            self.assertEqual(len(contract["animation_assets"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["diagrams"]), 1)
            self.assertEqual(len(lesson["generated_assets"]["animations"]), 1)
            self.assertIn("generated_lab", lesson["phases"]["simulation_inquiry"])
            self.assertGreaterEqual(len(contract["core_concepts"]), 4)
            self.assertGreaterEqual(len(contract["visual_clarity_checks"]), 3)
            self.assertTrue(simulation_contract["asset_id"])
            self.assertTrue(simulation_contract["concept"])
            self.assertTrue(simulation_contract["focus_prompt"])
            self.assertTrue(simulation_contract["baseline_case"])
            self.assertGreaterEqual(len(simulation_contract["controls"]), 3)
            self.assertGreaterEqual(len(simulation_contract["readouts"]), 3)
            self.assertGreaterEqual(len(simulation_contract["comparison_tasks"]), 2)

            skill_tags = set()
            for question in [*diagnostic_items, *concept_checks, *transfer_items]:
                if question["type"] == "short":
                    accepted = question.get("accepted_answers") or []
                    if accepted and not all(str(answer).strip().isdigit() for answer in accepted) and question.get("acceptance_rules"):
                        self.assertIn("phrase_groups", question.get("acceptance_rules", {}))
                self.assertTrue(question.get("skill_tags"))
                skill_tags.update(question.get("skill_tags") or [])
            self.assertGreaterEqual(len(skill_tags), 4)

    def test_m2_curriculum_scope_stays_on_forces_momentum_and_stability(self) -> None:
        mastery_text = " ".join(M2_MODULE_DOC.get("mastery_outcomes") or []).lower()
        self.assertIn("resultant force", mastery_text)
        self.assertIn("newton", mastery_text)
        self.assertIn("momentum", mastery_text)
        self.assertIn("stability", mastery_text)
        self.assertIn("vector", mastery_text)
        self.assertNotIn("density", mastery_text)
        self.assertNotIn("specific heat", mastery_text)


if __name__ == "__main__":
    unittest.main()
