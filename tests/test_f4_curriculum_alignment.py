import unittest

from scripts.seed_f4_module import F4_MODULE_DOC


class F4CurriculumAlignmentTests(unittest.TestCase):
    def test_f4_header_matches_refined_curriculum(self) -> None:
        self.assertEqual(F4_MODULE_DOC["id"], "F4")
        self.assertEqual(F4_MODULE_DOC["title"], "Waves, Light and Electricity")
        self.assertEqual(F4_MODULE_DOC["analogy_model_name"], "Signal-Glow Grid Model")
        self.assertIn("waves and vibrations", F4_MODULE_DOC.get("curriculum_focus") or [])
        self.assertIn("simple circuits", F4_MODULE_DOC.get("curriculum_focus") or [])
        self.assertIn("magnetic effects of current", F4_MODULE_DOC.get("curriculum_focus") or [])


if __name__ == "__main__":
    unittest.main()
