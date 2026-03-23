from __future__ import annotations

import importlib
import unittest

from app.common import normalize_module_id


class SeedA5ModuleTests(unittest.TestCase):
    def test_normalize_module_id_accepts_advanced_alias_prefix(self) -> None:
        self.assertEqual(normalize_module_id("MA5"), "A5")
        self.assertEqual(normalize_module_id("ma5"), "A5")

    def test_seed_a5_module_builds_successfully(self) -> None:
        module = importlib.import_module("scripts.seed_a5_module")

        self.assertEqual(module.A5_MODULE_DOC["id"], "A5")
        self.assertEqual(module.A5_MODULE_DOC["title"], "Oscillations")
        self.assertEqual(len(module.A5_LESSONS), 6)
        self.assertEqual(len(module.A5_SIM_LABS), 6)


if __name__ == "__main__":
    unittest.main()
