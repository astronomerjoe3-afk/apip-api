import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from app.agents.diagram_agent import generate_diagram
from app.agents.particle_physics_visual_agent import generate_particle_physics_visual
from app.agents.quantum_physics_visual_agent import generate_quantum_physics_visual
from app.agents.radioactivity_radiation_visual_agent import generate_radioactivity_radiation_visual
from app.agents.standard_physics_equation_agent import generate_standard_physics_equation
from app.lesson_pipeline.contracts import DIAGRAM_REQUEST_TEMPLATE_CONTRACTS


class ModernPhysicsVisualAgentsTests(unittest.TestCase):
    def test_contract_lists_modern_visual_templates(self) -> None:
        self.assertIn("standard_physics_equation", DIAGRAM_REQUEST_TEMPLATE_CONTRACTS)
        self.assertIn("particle_physics_visual", DIAGRAM_REQUEST_TEMPLATE_CONTRACTS)
        self.assertIn("quantum_physics_visual", DIAGRAM_REQUEST_TEMPLATE_CONTRACTS)
        self.assertIn("radioactivity_radiation_visual", DIAGRAM_REQUEST_TEMPLATE_CONTRACTS)
        self.assertIn(
            "double_slit_pattern",
            DIAGRAM_REQUEST_TEMPLATE_CONTRACTS["quantum_physics_visual"]["meta_contract"]["visual_type"],
        )

    def test_equation_agent_generates_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="equation_newton_02_01",
            phase_key="guided_concept_building",
            concept="standard_physics_equation",
            title="Newton's Second Law",
            description="Force, mass, and acceleration relation.",
            width=1280,
            height=720,
            meta={
                "equation_key": "newtons_second_law",
                "visual_type": "equation_card",
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_standard_physics_equation(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="MECH",
                lesson_id="MECH_L1",
            )
            path = Path(asset.storage_path)
            self.assertTrue(path.exists())
            svg = path.read_text(encoding="utf-8")
            self.assertIn("Newton", svg)
            self.assertIn("F = ma", svg)

    def test_particle_agent_generates_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="particle_hadron_01",
            phase_key="guided_concept_building",
            concept="particle_physics_visual",
            title="Proton Composition",
            description="Valence quarks in a proton.",
            width=1280,
            height=720,
            meta={
                "visual_type": "hadron_composition",
                "hadron_type": "proton",
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_particle_physics_visual(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="PP",
                lesson_id="PP_L1",
            )
            path = Path(asset.storage_path)
            self.assertTrue(path.exists())
            svg = path.read_text(encoding="utf-8")
            self.assertIn("Proton", svg)

    def test_quantum_agent_generates_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="quantum_levels_01",
            phase_key="guided_concept_building",
            concept="quantum_physics_visual",
            title="Quantized Energy Levels",
            description="Energy levels in an atom.",
            width=1280,
            height=720,
            meta={
                "visual_type": "energy_levels",
                "level_count": 4,
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_quantum_physics_visual(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="QM",
                lesson_id="QM_L1",
            )
            path = Path(asset.storage_path)
            self.assertTrue(path.exists())
            svg = path.read_text(encoding="utf-8")
            self.assertIn("Quantized Energy Levels", svg)

    def test_radiation_agent_generates_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="radiation_penetration_01",
            phase_key="guided_concept_building",
            concept="radioactivity_radiation_visual",
            title="Alpha Beta Gamma Penetration",
            description="Relative penetration of ionising radiations.",
            width=1280,
            height=720,
            meta={
                "visual_type": "alpha_beta_gamma_penetration",
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_radioactivity_radiation_visual(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="NUC",
                lesson_id="NUC_L1",
            )
            path = Path(asset.storage_path)
            self.assertTrue(path.exists())
            svg = path.read_text(encoding="utf-8")
            self.assertIn("Alpha", svg)
            self.assertIn("Gamma", svg)

    def test_router_accepts_new_visual_templates(self) -> None:
        req = SimpleNamespace(
            asset_id="equation_router_01",
            phase_key="guided_concept_building",
            concept="equation_card",
            template="standard_physics_equation",
            title="Ohm's Law",
            description="Voltage, current, and resistance relation.",
            width=1280,
            height=720,
            meta={
                "equation_key": "ohms_law",
                "visual_type": "equation_card",
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="ELEC",
                lesson_id="ELEC_L1",
            )
            self.assertEqual(asset.provider, "standard_physics_equation_agent")


if __name__ == "__main__":
    unittest.main()
