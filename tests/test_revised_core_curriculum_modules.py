from __future__ import annotations

import unittest

from app.services.catalog_bootstrap import get_catalog_module_ids, get_catalog_module_row
from scripts.revised_core_curriculum_modules import (
    F5_LESSONS,
    F5_MODULE_DOC,
    F5_SIM_LABS,
    M12_LESSONS,
    M12_MODULE_DOC,
    M12_SIM_LABS,
    M14_LESSONS,
    M14_MODULE_DOC,
    M14_SIM_LABS,
    M9_LESSONS,
    M9_MODULE_DOC,
    M9_SIM_LABS,
)


class RevisedCoreCurriculumModuleTests(unittest.TestCase):
    def test_revised_core_bundles_build_successfully(self) -> None:
        self.assertEqual(F5_MODULE_DOC["title"], "Observable Earth and Sky")
        self.assertEqual(M9_MODULE_DOC["title"], "Electrical Quantities and Circuits")
        self.assertEqual(M12_MODULE_DOC["title"], "Nuclear Energy and Applications")
        self.assertEqual(M14_MODULE_DOC["title"], "Stars and the Universe")
        self.assertEqual(len(F5_LESSONS), 6)
        self.assertEqual(len(F5_SIM_LABS), 6)
        self.assertEqual(len(M9_LESSONS), 6)
        self.assertEqual(len(M9_SIM_LABS), 6)
        self.assertEqual(len(M12_LESSONS), 6)
        self.assertEqual(len(M12_SIM_LABS), 6)
        self.assertEqual(len(M14_LESSONS), 6)
        self.assertEqual(len(M14_SIM_LABS), 6)

    def test_catalog_bootstrap_uses_revised_late_core_sequence(self) -> None:
        module_ids = get_catalog_module_ids()
        self.assertIn("F5", module_ids)
        self.assertIn("M14", module_ids)
        self.assertNotIn("M15", module_ids)
        self.assertEqual(get_catalog_module_row("M9")["title"], "Electrical Quantities and Circuits")
        self.assertEqual(get_catalog_module_row("M10")["title"], "Magnetism and Electromagnetic Effects")
        self.assertEqual(get_catalog_module_row("M11")["title"], "Atomic Structure and Radioactivity")
        self.assertEqual(get_catalog_module_row("M12")["title"], "Nuclear Energy and Applications")
        self.assertEqual(get_catalog_module_row("M13")["title"], "Earth and the Solar System")
        self.assertEqual(get_catalog_module_row("M14")["title"], "Stars and the Universe")
        self.assertIsNone(get_catalog_module_row("M15"))


if __name__ == "__main__":
    unittest.main()
