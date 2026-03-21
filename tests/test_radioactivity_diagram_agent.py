import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from app.agents.radioactivity_diagram_agent import generate_radioactivity_diagram


class RadioactivityDiagramAgentTests(unittest.TestCase):
    def test_generates_vault_house_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="m13_l1_vault_house",
            phase_key="analogical_grounding",
            concept="radioactivity_diagram",
            template="radioactivity_diagram",
            title="Build the Vault-House",
            description="Core Vault and Orbit Ring diagram.",
            width=1280,
            height=720,
            meta={
                "diagram_type": "vault_house",
                "proton_count": 6,
                "neutron_count": 8,
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_radioactivity_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="M13",
                lesson_id="M13_L1",
            )
            svg = Path(asset.storage_path).read_text(encoding="utf-8")
            self.assertIn("<svg", svg)
            self.assertIn("Build the Vault-House", svg)
            self.assertIn("Core Vault", svg)
            self.assertIn("Orbit Ring", svg)

    def test_generates_decay_ledger_svg(self) -> None:
        req = SimpleNamespace(
            asset_id="m13_l6_decay_ledger",
            phase_key="analogical_grounding",
            concept="radioactivity_diagram",
            template="radioactivity_diagram",
            title="Vault Ledger Boss",
            description="Decay-equation bookkeeping diagram.",
            width=1280,
            height=720,
            meta={
                "diagram_type": "decay_ledger",
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            asset = generate_radioactivity_diagram(
                req=req,
                output_dir=tmpdir,
                public_base="/lesson_assets",
                module_id="M13",
                lesson_id="M13_L6",
            )
            svg = Path(asset.storage_path).read_text(encoding="utf-8")
            self.assertIn("<svg", svg)
            self.assertIn("Vault Ledger Boss", svg)
            self.assertIn("alpha", svg)
            self.assertIn("gamma", svg)


if __name__ == "__main__":
    unittest.main()
