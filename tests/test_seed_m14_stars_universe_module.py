from __future__ import annotations

import importlib
import unittest


class SeedM14ModuleTests(unittest.TestCase):
    def test_seed_m14_stars_universe_module_builds_successfully(self) -> None:
        module = importlib.import_module("scripts.seed_m14_stars_universe_module")

        self.assertEqual(module.M14_MODULE_DOC["id"], "M14")
        self.assertEqual(module.M14_MODULE_DOC["title"], "Stars and the Universe")
        self.assertEqual(module.M14_MODULE_DOC["authoring_standard"], "lesson_authoring_spec_v3")
        self.assertEqual(len(module.M14_LESSONS), 6)
        self.assertEqual(len(module.M14_SIM_LABS), 6)


if __name__ == "__main__":
    unittest.main()
