from __future__ import annotations

import importlib
import unittest

from app.common import normalize_module_id


class SeedA2ModuleTests(unittest.TestCase):
    def test_normalize_module_id_accepts_advanced_alias_prefix(self) -> None:
        self.assertEqual(normalize_module_id("MA2"), "A2")
        self.assertEqual(normalize_module_id("ma2"), "A2")

    def test_seed_a2_module_builds_successfully(self) -> None:
        module = importlib.import_module("scripts.seed_a2_module")

        self.assertEqual(module.A2_MODULE_DOC["id"], "A2")
        self.assertEqual(module.A2_MODULE_DOC["title"], "Quantum Phenomena and Atomic Spectra")
        self.assertEqual(len(module.A2_LESSONS), 6)
        self.assertEqual(len(module.A2_SIM_LABS), 6)

    def test_seed_a2_visuals_use_general_visual_template(self) -> None:
        module = importlib.import_module("scripts.seed_a2_module")

        for _, lesson in module.A2_LESSONS:
            visuals = (lesson.get("authoring_contract") or {}).get("visual_assets") or []
            self.assertGreater(len(visuals), 0)
            for visual in visuals:
                self.assertEqual(visual.get("template"), "general_visual")
                self.assertTrue(visual.get("title"))


if __name__ == "__main__":
    unittest.main()
