from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.lesson_pipeline.contracts import LessonSpec
from app.lesson_pipeline.lesson_asset_orchestrator import compile_lesson_assets


def _spec() -> LessonSpec:
    return LessonSpec.from_dict(
        {
            "lesson_id": "F1_L1",
            "module_id": "F1",
            "title": "SI Units and Prefixes",
            "phases": {
                "analogical_grounding": {
                    "analogy_text": "Units are like currency denominations.",
                },
                "simulation_inquiry": {
                    "lab_id": "F1-LAB-UNITS-01",
                },
            },
            "asset_requests": {
                "diagrams": [
                    {
                        "asset_id": "f1_l1_prefix_ladder",
                        "phase_key": "analogical_grounding",
                        "concept": "prefix_scale",
                        "description": "Metric ladder for kilo to milli relationships",
                        "title": "Metric Prefix Ladder",
                    }
                ],
                "animations": [
                    {
                        "asset_id": "f1_l1_unit_conversion_anim",
                        "phase_key": "analogical_grounding",
                        "concept": "unit_conversion",
                        "description": "Animate 2.5 km becoming 2500 m",
                        "title": "Unit Conversion Animation",
                        "duration_sec": 8,
                    }
                ],
                "simulation": {
                    "asset_id": "f1_l1_precision_lab",
                    "phase_key": "simulation_inquiry",
                    "lab_id": "F1-LAB-UNITS-01",
                    "concept": "measurement_precision",
                    "description": "Interactive lab comparing ruler and caliper precision",
                    "title": "Measurement Precision Lab",
                },
            },
        }
    )


class LessonAssetOrchestratorTests(unittest.TestCase):
    def test_compile_lesson_assets_generates_files_and_phase_patch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            compiled = compile_lesson_assets(
                spec=_spec(),
                asset_root=tmp_dir,
                public_base="/lesson_assets",
            )

            generated_assets = compiled.generated_assets
            self.assertEqual(len(generated_assets["diagrams"]), 1)
            self.assertEqual(len(generated_assets["animations"]), 1)
            self.assertIsNotNone(generated_assets["simulation"])

            diagram_path = Path(generated_assets["diagrams"][0]["storage_path"])
            animation_path = Path(generated_assets["animations"][0]["storage_path"])
            simulation_path = Path(generated_assets["simulation"]["storage_path"])

            self.assertTrue(diagram_path.exists())
            self.assertTrue(animation_path.exists())
            self.assertTrue(simulation_path.exists())

            analogical_assets = compiled.lesson_patch["phases"]["analogical_grounding"]["assets"]
            self.assertEqual(len(analogical_assets), 2)
            self.assertEqual(analogical_assets[0]["kind"], "diagram")
            self.assertEqual(analogical_assets[1]["kind"], "animation")
            self.assertEqual(
                analogical_assets[0]["url"],
                "/lesson_assets/F1/F1_L1/diagrams/f1_l1_prefix_ladder.svg",
            )

            generated_lab = compiled.lesson_patch["phases"]["simulation_inquiry"]["generated_lab"]
            self.assertEqual(
                generated_lab["url"],
                "/lesson_assets/F1/F1_L1/simulations/F1-LAB-UNITS-01/index.html",
            )
