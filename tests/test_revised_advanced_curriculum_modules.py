from __future__ import annotations

import unittest

from app.services.catalog_bootstrap import get_catalog_module, get_catalog_module_ids


class RevisedAdvancedCurriculumModulesTests(unittest.TestCase):
    def test_catalog_bootstrap_includes_a6_to_a11(self) -> None:
        module_ids = set(get_catalog_module_ids())
        for module_id in ("A6", "A7", "A8", "A9", "A10", "A11"):
            self.assertIn(module_id, module_ids)

    def test_a6_to_a11_bundles_import_with_six_lessons(self) -> None:
        expected_titles = {
            "A6": "Thermal Physics and Gases",
            "A7": "DC Circuits and Capacitors",
            "A8": "Electric and Magnetic Fields",
            "A9": "Electromagnetic Induction and Power",
            "A10": "Nuclear and Particle Applications",
            "A11": "Astrophysics, Gravitation and Cosmology",
        }
        for module_id, expected_title in expected_titles.items():
            with self.subTest(module_id=module_id):
                bundle = get_catalog_module(module_id)
                self.assertIsNotNone(bundle)
                self.assertEqual(expected_title, bundle["module_doc"]["title"])
                self.assertEqual(6, len(bundle["lessons"]))
                self.assertEqual(6, len(bundle["sim_labs"]))


if __name__ == "__main__":
    unittest.main()
