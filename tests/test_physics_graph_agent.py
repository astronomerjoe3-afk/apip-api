import shutil
import unittest
from pathlib import Path
from types import SimpleNamespace

from app.agents.physics_graph_agent import generate_physics_graph


def _writable_temp_dir(name: str) -> Path:
    root = Path(__file__).resolve().parents[1] / ".codex_tmp_assets" / "physics_graph_tests"
    path = root / name
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    return path


class PhysicsGraphAgentTests(unittest.TestCase):
    def test_generates_projectile_trajectory_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="projectile_graph_01",
            phase_key="guided_concept_building",
            concept="physics_graph",
            title="Projectile Trajectory",
            description="Projectile path under uniform gravity.",
            width=1280,
            height=720,
            meta={
                "graph_type": "projectile_trajectory",
                "title": "Projectile Trajectory",
                "subtitle": "v = 20 m/s, angle = 45 deg",
                "x_label": "Horizontal distance (m)",
                "y_label": "Vertical height (m)",
                "speed": 20,
                "launch_angle_deg": 45,
                "gravity": 9.81,
            },
        )

        tmpdir = _writable_temp_dir("projectile_case")
        try:
            asset = generate_physics_graph(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="MECH",
                lesson_id="MECH_L1",
            )
            svg = Path(asset.storage_path).read_text(encoding="utf-8")
            self.assertIn("<svg", svg)
            self.assertIn("Projectile Trajectory", svg)
            self.assertIn("Horizontal distance (m)", svg)
            self.assertIn("Vertical height (m)", svg)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_generates_circular_motion_xy_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="circular_motion_xy_01",
            phase_key="guided_concept_building",
            concept="physics_graph",
            title="Circular Motion Path",
            description="Object moving in a circle.",
            width=1280,
            height=720,
            meta={
                "graph_type": "circular_motion_xy",
                "title": "Circular Motion Path",
                "subtitle": "Uniform circular motion in the x-y plane",
                "x_label": "x position (m)",
                "y_label": "y position (m)",
                "radius": 2.5,
            },
        )

        tmpdir = _writable_temp_dir("circular_case")
        try:
            asset = generate_physics_graph(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="MECH",
                lesson_id="MECH_L2",
            )
            svg = Path(asset.storage_path).read_text(encoding="utf-8")
            self.assertIn("<svg", svg)
            self.assertIn("Circular Motion Path", svg)
            self.assertIn("x position (m)", svg)
            self.assertIn("y position (m)", svg)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_generates_generic_xy_svg_with_area_fill(self) -> None:
        req = SimpleNamespace(
            asset_id="generic_xy_01",
            phase_key="guided_concept_building",
            concept="physics_graph",
            title="Velocity-Time Graph",
            description="Simple velocity-time graph.",
            width=1280,
            height=720,
            meta={
                "graph_type": "generic_xy",
                "title": "Velocity-Time Graph",
                "x_label": "Time (s)",
                "y_label": "Velocity (m/s)",
                "fill_under_series": True,
                "series": [
                    {
                        "label": "v(t)",
                        "points": [[0, 0], [1, 2], [2, 4], [3, 4], [4, 1]],
                    }
                ],
                "annotations": [
                    {"x": 2.2, "y": 2.0, "text": "Area = displacement"},
                ],
            },
        )

        tmpdir = _writable_temp_dir("generic_case")
        try:
            asset = generate_physics_graph(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="MECH",
                lesson_id="MECH_L3",
            )
            svg = Path(asset.storage_path).read_text(encoding="utf-8")
            self.assertIn("<svg", svg)
            self.assertIn("Velocity-Time Graph", svg)
            self.assertIn("Time (s)", svg)
            self.assertIn("Velocity (m/s)", svg)
            self.assertIn("Area = displacement", svg)
            self.assertIn("<polygon", svg)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
