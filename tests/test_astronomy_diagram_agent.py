import shutil
import unittest
from pathlib import Path
from types import SimpleNamespace

from app.agents.astronomy_diagram_agent import generate_astronomy_diagram


def _writable_temp_dir(name: str) -> Path:
    root = Path(__file__).resolve().parents[1] / ".codex_tmp_assets" / "astronomy_tests"
    path = root / name
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    return path


class AstronomyDiagramAgentTests(unittest.TestCase):
    def test_generates_solar_court_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="m14_l1_solar_court",
            phase_key="analogical_grounding",
            concept="astronomy_diagram",
            template="astronomy_diagram",
            title="Build the Solar Court",
            description="Sun-centered family diagram.",
            width=1280,
            height=720,
            meta={
                "diagram_type": "solar_court",
            },
        )

        tmpdir = _writable_temp_dir("solar_court_case")
        try:
            asset = generate_astronomy_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="M14",
                lesson_id="M14_L1",
            )
            svg = Path(asset.storage_path).read_text(encoding="utf-8")
            self.assertIn("<svg", svg)
            self.assertIn("Build the Solar Court", svg)
            self.assertIn("Sun", svg)
            self.assertIn("rock swarm", svg)
            self.assertIn("ice visitor", svg)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_generates_moon_phase_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="m14_l5_moon_face_challenge",
            phase_key="analogical_grounding",
            concept="astronomy_diagram",
            template="astronomy_diagram",
            title="Moon Face Challenge",
            description="Moon phase geometry diagram.",
            width=1280,
            height=720,
            meta={
                "diagram_type": "moon_phases",
                "moon_position": 4,
            },
        )

        tmpdir = _writable_temp_dir("moon_phase_case")
        try:
            asset = generate_astronomy_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="M14",
                lesson_id="M14_L5",
            )
            svg = Path(asset.storage_path).read_text(encoding="utf-8")
            self.assertIn("<svg", svg)
            self.assertIn("Moon Face Challenge", svg)
            self.assertIn("always half lit", svg)
            self.assertIn("Shown phase:", svg)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
