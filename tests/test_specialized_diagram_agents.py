import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from app.agents.electric_circuit_diagram_agent import generate_electric_circuit_diagram
from app.agents.electromagnetism_diagram_agent import generate_electromagnetism_diagram
from app.agents.wave_diagram_agent import generate_wave_diagram


class SpecializedDiagramAgentsTests(unittest.TestCase):
    def test_generates_electric_circuit_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="circuit_series_01",
            phase_key="guided_concept_building",
            concept="electric_circuit_diagram",
            template="electric_circuit_diagram",
            title="Simple Series Circuit",
            description="Battery, switch, lamp, and resistor in series.",
            width=1280,
            height=720,
            meta={
                "circuit_type": "simple_series",
                "closed_switch": True,
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_electric_circuit_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="ELEC",
                lesson_id="ELEC_L1",
            )
            path = Path(asset.storage_path)
            self.assertTrue(path.exists())
            svg = path.read_text(encoding="utf-8")
            self.assertIn("<svg", svg)
            self.assertIn("Simple Series Circuit", svg)
            self.assertIn("Lamp", svg)
            self.assertIn("Resistor", svg)

    def test_generates_wave_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="wave_transverse_01",
            phase_key="analogical_grounding",
            concept="wave_diagram",
            template="wave_diagram",
            title="Transverse Wave",
            description="Amplitude and wavelength diagram.",
            width=1280,
            height=720,
            meta={
                "wave_type": "transverse_wave",
                "wavelength_count": 2,
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_wave_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="WAVES",
                lesson_id="WAVES_L1",
            )
            path = Path(asset.storage_path)
            self.assertTrue(path.exists())
            svg = path.read_text(encoding="utf-8")
            self.assertIn("<svg", svg)
            self.assertIn("Transverse Wave", svg)
            self.assertIn("Wavelength", svg)

    def test_generates_wave_equation_svg_with_separate_formula_badge(self) -> None:
        req = SimpleNamespace(
            asset_id="wave_equation_01",
            phase_key="analogical_grounding",
            concept="wave_diagram",
            template="wave_diagram",
            title="Beat Rate, Pulse Gap, and Ripple Run",
            description="Shows launch rate, front spacing, and front speed on one board.",
            width=1280,
            height=720,
            meta={
                "wave_type": "wave_equation",
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_wave_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="M7",
                lesson_id="M7_L3",
            )
            path = Path(asset.storage_path)
            self.assertTrue(path.exists())
            svg = path.read_text(encoding="utf-8")
            self.assertIn('rect x="440.00" y="118.00" width="400.00" height="70.00"', svg)
            self.assertIn('rect x="90.00" y="210.00" width="1100.00" height="360.00"', svg)
            self.assertIn('rect x="130.00" y="280.00" width="280.00" height="210.00"', svg)
            self.assertIn("v = f lambda", svg)

    def test_generates_electromagnetism_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="em_bar_magnet_01",
            phase_key="guided_concept_building",
            concept="electromagnetism_diagram",
            template="electromagnetism_diagram",
            title="Bar Magnet Field",
            description="Magnetic field around a bar magnet.",
            width=1280,
            height=720,
            meta={
                "diagram_type": "bar_magnet_field",
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_electromagnetism_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="EM",
                lesson_id="EM_L1",
            )
            path = Path(asset.storage_path)
            self.assertTrue(path.exists())
            svg = path.read_text(encoding="utf-8")
            self.assertIn("<svg", svg)
            self.assertIn("Bar Magnet Field", svg)
            self.assertIn("N", svg)
            self.assertIn("S", svg)

    def test_generates_flux_window_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="flux_window_01",
            phase_key="guided_concept_building",
            concept="electromagnetism_diagram",
            template="electromagnetism_diagram",
            title="Catch the Field Threads",
            description="Flux as field through a loop window.",
            width=1280,
            height=720,
            meta={
                "diagram_type": "flux_window",
                "loop_tilt_deg": 25,
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_electromagnetism_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="A3",
                lesson_id="A3_L1",
            )
            path = Path(asset.storage_path)
            self.assertTrue(path.exists())
            svg = path.read_text(encoding="utf-8")
            self.assertIn("Catch the Field Threads", svg)
            self.assertIn("through the window", svg)
            self.assertIn("window normal", svg)

    def test_generates_lenz_opposition_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="lenz_opposition_01",
            phase_key="guided_concept_building",
            concept="electromagnetism_diagram",
            template="electromagnetism_diagram",
            title="Oppose-Turn Rule",
            description="Induced response opposes the flux change.",
            width=1280,
            height=720,
            meta={
                "diagram_type": "lenz_opposition",
                "change_direction": "increasing_inward",
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_electromagnetism_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="A3",
                lesson_id="A3_L4",
            )
            path = Path(asset.storage_path)
            self.assertTrue(path.exists())
            svg = path.read_text(encoding="utf-8")
            self.assertIn("Oppose-Turn Rule", svg)
            self.assertIn("opposes the change", svg)
            self.assertIn("induced field", svg)

    def test_generates_reflection_wave_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="wave_reflection_01",
            phase_key="guided_concept_building",
            concept="wave_diagram",
            template="wave_diagram",
            title="Wave Reflection",
            description="Reflection at a flat wall.",
            width=1280,
            height=720,
            meta={
                "wave_type": "reflection",
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_wave_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="WAVES",
                lesson_id="WAVES_L4",
            )
            path = Path(asset.storage_path)
            self.assertTrue(path.exists())
            svg = path.read_text(encoding="utf-8")
            self.assertIn("Wave Reflection", svg)
            self.assertIn("incident", svg)
            self.assertIn("reflected", svg)

    def test_generates_refraction_wave_svg_with_internal_medium_labels(self) -> None:
        req = SimpleNamespace(
            asset_id="wave_refraction_01",
            phase_key="guided_concept_building",
            concept="wave_diagram",
            template="wave_diagram",
            title="Bend Gate boundary turn",
            description="Toward the Guide Line in a slower zone, away from it in a faster zone",
            width=1280,
            height=720,
            meta={
                "wave_type": "refraction",
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_wave_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="M8",
                lesson_id="M8_L2",
            )
            path = Path(asset.storage_path)
            self.assertTrue(path.exists())
            svg = path.read_text(encoding="utf-8")
            self.assertIn('text x="410.00" y="272.00"', svg)
            self.assertIn('text x="895.00" y="272.00"', svg)
            self.assertNotIn('text x="330.00" y="220.00"', svg)
            self.assertNotIn('text x="1010.00" y="220.00"', svg)

    def test_generates_critical_angle_wave_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="wave_critical_angle_01",
            phase_key="guided_concept_building",
            concept="wave_diagram",
            template="wave_diagram",
            title="Critical Angle Story",
            description="Compare escape, skim, and lock-bounce.",
            width=1280,
            height=720,
            meta={
                "wave_type": "critical_angle",
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_wave_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="LIGHT",
                lesson_id="M8_L5",
            )
            path = Path(asset.storage_path)
            self.assertTrue(path.exists())
            svg = path.read_text(encoding="utf-8")
            self.assertIn("Critical Angle Story", svg)
            self.assertIn("Below critical", svg)
            self.assertIn("At critical", svg)
            self.assertIn("Above critical", svg)

    def test_generates_optical_fiber_wave_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="wave_optical_fiber_01",
            phase_key="guided_concept_building",
            concept="wave_diagram",
            template="wave_diagram",
            title="Optical Fiber",
            description="Repeated lock-bounce in the core.",
            width=1280,
            height=720,
            meta={
                "wave_type": "optical_fiber",
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_wave_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="LIGHT",
                lesson_id="M8_L5",
            )
            path = Path(asset.storage_path)
            self.assertTrue(path.exists())
            svg = path.read_text(encoding="utf-8")
            self.assertIn("Optical Fiber", svg)
            self.assertIn("core", svg)
            self.assertIn("cladding", svg)

    def test_generates_loop_ledger_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="loop_ledger_01",
            phase_key="guided_concept_building",
            concept="electric_circuit_diagram",
            template="electric_circuit_diagram",
            title="Loop Ledger",
            description="Compare two loops with the same source.",
            width=1280,
            height=720,
            meta={
                "circuit_type": "loop_ledger",
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_electric_circuit_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="ELEC",
                lesson_id="ELEC_L6",
            )
            path = Path(asset.storage_path)
            self.assertTrue(path.exists())
            svg = path.read_text(encoding="utf-8")
            self.assertIn("Loop Ledger", svg)
            self.assertIn("Loop A", svg)
            self.assertIn("Loop B", svg)


if __name__ == "__main__":
    unittest.main()
