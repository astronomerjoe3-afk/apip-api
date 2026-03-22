import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app.agents.general_visual_concept_agent import generate_general_visual_concept


class GeneralVisualConceptAgentTests(unittest.TestCase):
    def test_generates_placeholder_when_no_openai_key(self) -> None:
        req = SimpleNamespace(
            asset_id="general_visual_01",
            phase_key="guided_concept_building",
            concept="general_visual",
            title="Powerful Physics Learning Visual",
            description="A bold concept image for adaptive learning.",
            width=1280,
            height=720,
            meta={
                "style": "cinematic educational concept art",
                "subject": "AI-guided physics learning",
                "mood": "powerful, visionary",
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"OPENAI_API_KEY": ""}):
                asset = generate_general_visual_concept(
                    req=req,
                    output_dir=tmpdir,
                    public_base="/lesson_assets",
                    module_id="F1",
                    lesson_id="F1_L1",
                )

            path = Path(asset.storage_path)
            self.assertTrue(path.exists())
            self.assertEqual(asset.kind, "diagram")
            self.assertIn(asset.mime_type, {"image/svg+xml", "image/png", "image/jpeg", "image/webp"})

            content = path.read_text(encoding="utf-8")
            self.assertIn("<svg", content)
            self.assertIn("Powerful Physics Learning Visual", content)


if __name__ == "__main__":
    unittest.main()
