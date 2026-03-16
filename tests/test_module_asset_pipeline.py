from __future__ import annotations

import unittest

from scripts.module_asset_pipeline import plan_lesson_assets
from scripts.seed_m3_module import M3_LESSONS, M3_MODULE_DOC, M3_SIM_LABS


class ModuleAssetPipelineTests(unittest.TestCase):
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
            simulation["url"],
            "/lesson_assets/M3/M3_LX/simulations/m3_network_rules_lab/index.html",
        )

    def test_m3_bundle_includes_planned_generated_assets(self) -> None:
        self.assertEqual(M3_MODULE_DOC["id"], "M3")
        self.assertEqual(len(M3_LESSONS), 6)
        self.assertEqual(len(M3_SIM_LABS), 6)

        lesson_id, lesson = M3_LESSONS[0]
        self.assertEqual(lesson_id, "M3_L1")
        self.assertIn("generated_assets", lesson)
        self.assertEqual(len(lesson["generated_assets"]["diagrams"]), 1)
        self.assertEqual(len(lesson["generated_assets"]["animations"]), 1)
        self.assertEqual(
            lesson["phases"]["simulation_inquiry"]["generated_lab"]["url"],
            "/lesson_assets/M3/M3_L1/simulations/m3_work_transfer_lab/index.html",
        )


if __name__ == "__main__":
    unittest.main()
