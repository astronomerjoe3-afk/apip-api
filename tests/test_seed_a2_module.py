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
        self.assertEqual(len(module.A2_LESSONS), 6)
        self.assertEqual(len(module.A2_SIM_LABS), 6)


if __name__ == "__main__":
    unittest.main()
