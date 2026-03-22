from __future__ import annotations

import importlib
import unittest


class SeedM15ModuleTests(unittest.TestCase):
    def test_seed_m15_module_builds_successfully(self) -> None:
        module = importlib.import_module("scripts.seed_m15_module")

        self.assertEqual(module.M15_MODULE_DOC["id"], "M15")
        self.assertEqual(module.M15_MODULE_DOC["title"], "Universe")
        self.assertEqual(module.M15_MODULE_DOC["authoring_standard"], "lesson_authoring_spec_v3")
        self.assertEqual(len(module.M15_LESSONS), 6)
        self.assertEqual(len(module.M15_SIM_LABS), 6)


if __name__ == "__main__":
    unittest.main()
