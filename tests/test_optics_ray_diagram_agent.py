import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from app.agents.optics_ray_diagram_agent import generate_optics_ray_diagram


class OpticsRayDiagramAgentTests(unittest.TestCase):
    def test_generates_converging_lens_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="optics_convex_lens_real_image_01",
            phase_key="analogical_grounding",
            concept="optics_ray_diagram",
            template="optics_ray_diagram",
            title="Converging Lens: Real Image",
            description="Principal-ray diagram for a converging lens.",
            width=1280,
            height=720,
            meta={
                "system_type": "converging_lens",
                "object_distance": 3.0,
                "focal_length": 1.2,
                "object_height": 1.0,
                "principal_rays": 3,
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_optics_ray_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="OPTICS",
                lesson_id="OPT_L1",
            )

            output_path = Path(asset.storage_path)
            self.assertTrue(output_path.exists())

            svg = output_path.read_text(encoding="utf-8")
            self.assertIn("<svg", svg)
            self.assertIn("Converging Lens: Real Image", svg)
            self.assertIn("Object", svg)
            self.assertIn("Image", svg)
            self.assertIn("optical axis", svg)

    def test_generates_convex_mirror_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="optics_convex_mirror_virtual_01",
            phase_key="guided_concept_building",
            concept="optics_ray_diagram",
            template="optics_ray_diagram",
            title="Convex Mirror: Virtual Image",
            description="Principal-ray diagram for a convex mirror.",
            width=1280,
            height=720,
            meta={
                "system_type": "convex_mirror",
                "object_distance": 3.0,
                "focal_length": 1.0,
                "object_height": 1.0,
                "principal_rays": 2,
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_optics_ray_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="OPTICS",
                lesson_id="OPT_L2",
            )

            output_path = Path(asset.storage_path)
            self.assertTrue(output_path.exists())

            svg = output_path.read_text(encoding="utf-8")
            self.assertIn("<svg", svg)
            self.assertIn("Convex Mirror: Virtual Image", svg)
            self.assertIn("Object", svg)
            self.assertIn("Image", svg)

    def test_generates_plane_mirror_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="optics_plane_mirror_equal_angles_01",
            phase_key="analogical_grounding",
            concept="optics_ray_diagram",
            template="optics_ray_diagram",
            title="Plane Mirror: Equal Angles",
            description="Plane-mirror diagram for M8 reflection support.",
            width=1280,
            height=720,
            meta={
                "system_type": "plane_mirror",
                "object_distance": 2.6,
                "focal_length": 1.0,
                "object_height": 1.1,
                "principal_rays": 3,
                "annotation_mode": "equal_angles",
                "incident_angle_deg": 35.0,
                "guide_line_angle_deg": 35.0,
                "show_focal_labels": False,
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_optics_ray_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="OPTICS",
                lesson_id="OPT_L3",
            )

            output_path = Path(asset.storage_path)
            self.assertTrue(output_path.exists())

            svg = output_path.read_text(encoding="utf-8")
            self.assertIn("<svg", svg)
            self.assertIn("Plane Mirror: Equal Angles", svg)
            self.assertIn("Guide Line", svg)
            self.assertIn("equal angles", svg)
            self.assertIn("Image", svg)


if __name__ == "__main__":
    unittest.main()
