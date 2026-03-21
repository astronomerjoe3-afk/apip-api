from __future__ import annotations

import importlib
import unittest

from app.common import normalize_module_id


class SeedA1ModuleTests(unittest.TestCase):
    def test_normalize_module_id_accepts_advanced_alias_prefix(self) -> None:
        self.assertEqual(normalize_module_id("MA1"), "A1")
        self.assertEqual(normalize_module_id("ma1"), "A1")

    def test_seed_a1_module_builds_successfully(self) -> None:
        module = importlib.import_module("scripts.seed_a1_module")

        self.assertEqual(module.A1_MODULE_DOC["id"], "A1")
        self.assertEqual(len(module.A1_LESSONS), 6)
        self.assertEqual(len(module.A1_SIM_LABS), 6)


if __name__ == "__main__":
    unittest.main()
