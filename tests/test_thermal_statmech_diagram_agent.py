import shutil
import unittest
from pathlib import Path
from types import SimpleNamespace

from app.agents.thermal_statmech_diagram_agent import generate_thermal_statmech_diagram


def _writable_temp_dir(name: str) -> Path:
    root = Path(__file__).resolve().parents[1] / ".codex_tmp_assets" / "thermal_statmech_tests"
    path = root / name
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    return path


class ThermalStatMechDiagramAgentTests(unittest.TestCase):
    def test_generates_bounce_chamber_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="a4_l1_bounce_chamber_pressure",
            phase_key="analogical_grounding",
            concept="thermal_statmech_diagram",
            template="thermal_statmech_diagram",
            title="Pressure as Wall-Hit Load",
            description="Bounce-chamber pressure diagram.",
            width=1280,
            height=720,
            meta={
                "diagram_type": "bounce_chamber_pressure",
                "particle_count": 12,
            },
        )

        tmpdir = _writable_temp_dir("bounce_chamber_case")
        try:
            asset = generate_thermal_statmech_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="A4",
                lesson_id="A4_L1",
            )
            svg = Path(asset.storage_path).read_text(encoding="utf-8")
            self.assertIn("<svg", svg)
            self.assertIn("Pressure as Wall-Hit Load", svg)
            self.assertIn("wall-hit load = pressure", svg)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_generates_entropy_option_count_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="a4_l6_entropy_option_count",
            phase_key="analogical_grounding",
            concept="thermal_statmech_diagram",
            template="thermal_statmech_diagram",
            title="Entropy as Spread Score",
            description="Option-count entropy diagram.",
            width=1280,
            height=720,
            meta={
                "diagram_type": "entropy_option_count",
            },
        )

        tmpdir = _writable_temp_dir("entropy_option_case")
        try:
            asset = generate_thermal_statmech_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="A4",
                lesson_id="A4_L6",
            )
            svg = Path(asset.storage_path).read_text(encoding="utf-8")
            self.assertIn("<svg", svg)
            self.assertIn("Entropy as Spread Score", svg)
            self.assertIn("S = k ln W", svg)
            self.assertIn("larger W", svg)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
