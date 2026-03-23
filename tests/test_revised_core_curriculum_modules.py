from __future__ import annotations

import unittest

from app.services.catalog_bootstrap import get_catalog_module_ids, get_catalog_module_row
from scripts.seed_m1_module import M1_MODULE_DOC
from scripts.seed_m2_module import M2_MODULE_DOC
from scripts.seed_m3_module import M3_MODULE_DOC
from scripts.seed_m4_module import M4_MODULE_DOC
from scripts.seed_m5_module import M5_MODULE_DOC
from scripts.seed_m6_module import M6_MODULE_DOC
from scripts.seed_m7_module import M7_MODULE_DOC
from scripts.seed_m8_module import M8_MODULE_DOC
from scripts.revised_core_curriculum_modules import (
    F5_LESSONS,
    F5_MODULE_DOC,
    F5_SIM_LABS,
    M10_MODULE_DOC,
    M11_MODULE_DOC,
    M12_LESSONS,
    M12_MODULE_DOC,
    M12_SIM_LABS,
    M13_MODULE_DOC,
    M14_LESSONS,
    M14_MODULE_DOC,
    M14_SIM_LABS,
    M9_LESSONS,
    M9_MODULE_DOC,
    M9_SIM_LABS,
)


class RevisedCoreCurriculumModuleTests(unittest.TestCase):
    EXPECTED_M1_TO_M14_TITLES = {
        "M1": "Motion and Kinematics",
        "M2": "Forces and Equilibrium",
        "M3": "Momentum, Work, Energy and Power",
        "M4": "Materials, Density and Pressure",
        "M5": "Particle Model and Internal Energy",
        "M6": "Thermal Transfer and Gas Behaviour",
        "M7": "Waves and Vibrations",
        "M8": "Light and Optics",
        "M9": "Electrical Quantities and Circuits",
        "M10": "Magnetism and Electromagnetic Effects",
        "M11": "Atomic Structure and Radioactivity",
        "M12": "Nuclear Energy and Applications",
        "M13": "Earth and the Solar System",
        "M14": "Stars and the Universe",
    }

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

    def test_live_m1_to_m14_bundle_titles_match_revised_curriculum(self) -> None:
        module_docs = {
            "M1": M1_MODULE_DOC,
            "M2": M2_MODULE_DOC,
            "M3": M3_MODULE_DOC,
            "M4": M4_MODULE_DOC,
            "M5": M5_MODULE_DOC,
            "M6": M6_MODULE_DOC,
            "M7": M7_MODULE_DOC,
            "M8": M8_MODULE_DOC,
            "M9": M9_MODULE_DOC,
            "M10": M10_MODULE_DOC,
            "M11": M11_MODULE_DOC,
            "M12": M12_MODULE_DOC,
            "M13": M13_MODULE_DOC,
            "M14": M14_MODULE_DOC,
        }
        for module_id, expected_title in self.EXPECTED_M1_TO_M14_TITLES.items():
            self.assertEqual(module_docs[module_id]["title"], expected_title)

    def test_catalog_bootstrap_uses_revised_late_core_sequence(self) -> None:
        module_ids = get_catalog_module_ids()
        self.assertIn("F5", module_ids)
        self.assertIn("M14", module_ids)
        self.assertNotIn("M15", module_ids)
        for module_id, expected_title in self.EXPECTED_M1_TO_M14_TITLES.items():
            self.assertEqual(get_catalog_module_row(module_id)["title"], expected_title)
        self.assertIsNone(get_catalog_module_row("M15"))


if __name__ == "__main__":
    unittest.main()
