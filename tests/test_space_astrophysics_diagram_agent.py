import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from app.agents.diagram_agent import generate_diagram
from app.agents.space_astrophysics_diagram_agent import generate_space_astrophysics_diagram
from app.lesson_pipeline.contracts import DIAGRAM_REQUEST_TEMPLATE_CONTRACTS


class SpaceAstrophysicsDiagramAgentTests(unittest.TestCase):
    def test_contract_lists_space_astrophysics_template(self) -> None:
        contract = DIAGRAM_REQUEST_TEMPLATE_CONTRACTS.get("space_astrophysics_diagram")
        self.assertIsNotNone(contract)
        self.assertIn("solar_system_overview", contract["meta_contract"]["diagram_type"])
        self.assertIn("astronomy_diagram", contract["concept_aliases"])

    def test_generates_solar_system_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="solar_system_overview_01",
            phase_key="guided_concept_building",
            concept="space_astrophysics_diagram",
            title="Solar System Overview",
            description="Inner planets and Jupiter shown around the Sun.",
            width=1280,
            height=720,
            meta={
                "diagram_type": "solar_system_overview",
                "highlighted_body": "Earth",
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_space_astrophysics_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="SPACE",
                lesson_id="SPACE_L1",
            )
            path = Path(asset.storage_path)
            self.assertTrue(path.exists())

            svg = path.read_text(encoding="utf-8")
            self.assertIn("<svg", svg)
            self.assertIn("Solar System Overview", svg)
            self.assertIn("Sun", svg)
            self.assertIn("Earth", svg)

    def test_generates_lunar_phases_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="lunar_phases_01",
            phase_key="analogical_grounding",
            concept="space_astrophysics_diagram",
            title="Lunar Phases",
            description="Moon phases around Earth.",
            width=1280,
            height=720,
            meta={
                "diagram_type": "lunar_phases",
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_space_astrophysics_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="SPACE",
                lesson_id="SPACE_L2",
            )
            path = Path(asset.storage_path)
            self.assertTrue(path.exists())

            svg = path.read_text(encoding="utf-8")
            self.assertIn("Lunar Phases", svg)
            self.assertIn("Earth", svg)
            self.assertIn("Full Moon", svg)

    def test_generates_hr_diagram_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="hr_diagram_01",
            phase_key="guided_concept_building",
            concept="space_astrophysics_diagram",
            title="H-R Diagram",
            description="Temperature versus luminosity.",
            width=1280,
            height=720,
            meta={
                "diagram_type": "hr_diagram",
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_space_astrophysics_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="SPACE",
                lesson_id="SPACE_L3",
            )
            path = Path(asset.storage_path)
            self.assertTrue(path.exists())

            svg = path.read_text(encoding="utf-8")
            self.assertIn("H-R Diagram", svg)
            self.assertIn("Main Sequence", svg)
            self.assertIn("White Dwarfs", svg)

    def test_router_accepts_space_astrophysics_template(self) -> None:
        req = SimpleNamespace(
            asset_id="stellar_lifecycle_01",
            phase_key="guided_concept_building",
            concept="astronomy_diagram",
            template="space_astrophysics_diagram",
            title="Stellar Lifecycle",
            description="How stars evolve over time.",
            width=1280,
            height=720,
            meta={
                "diagram_type": "stellar_lifecycle",
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="SPACE",
                lesson_id="SPACE_L4",
            )
            path = Path(asset.storage_path)
            self.assertTrue(path.exists())
            self.assertEqual(asset.provider, "space_astrophysics_diagram_agent")
            svg = path.read_text(encoding="utf-8")
            self.assertIn("Stellar Lifecycle", svg)
            self.assertIn("Main Sequence Star", svg)


if __name__ == "__main__":
    unittest.main()
