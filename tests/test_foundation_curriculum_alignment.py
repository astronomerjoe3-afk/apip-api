import unittest

from scripts.revised_core_curriculum_modules import F5_MODULE_DOC
from scripts.seed_f1_module import F1_MODULE_DOC
from scripts.seed_f2_module import F2_MODULE_DOC
from scripts.seed_f3_module import F3_MODULE_DOC
from scripts.seed_f4_module import F4_MODULE_DOC


class FoundationCurriculumAlignmentTests(unittest.TestCase):
    def test_f1_to_f5_title_sequence_matches_refined_curriculum(self) -> None:
        self.assertEqual(
            [
                F1_MODULE_DOC["title"],
                F2_MODULE_DOC["title"],
                F3_MODULE_DOC["title"],
                F4_MODULE_DOC["title"],
                F5_MODULE_DOC["title"],
            ],
            [
                "Scientific Measurement and Representation",
                "Motion, Forces and Energy",
                "Matter, Particles and Thermal Behaviour",
                "Waves, Light and Electricity",
                "Observable Earth and Sky",
            ],
        )

    def test_f1_matches_refined_curriculum_identity(self) -> None:
        mastery_text = " ".join(F1_MODULE_DOC.get("mastery_outcomes") or []).lower()
        focus = " ".join(F1_MODULE_DOC.get("curriculum_focus") or []).lower()

        self.assertEqual(F1_MODULE_DOC["title"], "Scientific Measurement and Representation")
        self.assertEqual(F1_MODULE_DOC["analogy_model_name"], "Measure-Map Studio Model")
        self.assertIn("tagged with units", F1_MODULE_DOC["anchor_sentence"].lower())
        self.assertIn("base and derived quantities", focus)
        self.assertIn("simple graphs", focus)
        self.assertIn("density", mastery_text)
        self.assertIn("graphs", mastery_text)

    def test_f2_matches_refined_curriculum_identity(self) -> None:
        description = str(F2_MODULE_DOC.get("description") or F2_MODULE_DOC.get("module_description") or "").lower()
        mastery_text = " ".join(F2_MODULE_DOC.get("mastery_outcomes") or []).lower()
        focus = " ".join(F2_MODULE_DOC.get("curriculum_focus") or []).lower()

        self.assertEqual(F2_MODULE_DOC["title"], "Motion, Forces and Energy")
        self.assertEqual(F2_MODULE_DOC["analogy_model_name"], "Mission-Track Model")
        self.assertIn("energy tokens", F2_MODULE_DOC["anchor_sentence"].lower())
        self.assertIn("distance and displacement", focus)
        self.assertIn("work done", focus)
        self.assertIn("conservation of energy", focus)
        self.assertIn("simple motion graphs", description)
        self.assertIn("power", mastery_text)

    def test_f3_matches_refined_curriculum_identity(self) -> None:
        description = str(F3_MODULE_DOC.get("description") or F3_MODULE_DOC.get("module_description") or "").lower()
        mastery_text = " ".join(F3_MODULE_DOC.get("mastery_outcomes") or []).lower()
        focus = " ".join(F3_MODULE_DOC.get("curriculum_focus") or []).lower()

        self.assertEqual(F3_MODULE_DOC["title"], "Matter, Particles and Thermal Behaviour")
        self.assertEqual(F3_MODULE_DOC["analogy_model_name"], "Pulse-Hearth Model")
        self.assertIn("tiny movers", F3_MODULE_DOC["anchor_sentence"].lower())
        self.assertIn("particle model of matter", focus)
        self.assertIn("change of state", focus)
        self.assertIn("conduction, convection, and radiation", focus)
        self.assertIn("pressure as particle collisions", description)
        self.assertIn("internal energy", mastery_text)

    def test_f4_matches_refined_curriculum_identity(self) -> None:
        description = str(F4_MODULE_DOC.get("description") or F4_MODULE_DOC.get("module_description") or "").lower()
        mastery_text = " ".join(F4_MODULE_DOC.get("mastery_outcomes") or []).lower()
        focus = " ".join(F4_MODULE_DOC.get("curriculum_focus") or []).lower()

        self.assertEqual(F4_MODULE_DOC["title"], "Waves, Light and Electricity")
        self.assertEqual(F4_MODULE_DOC["analogy_model_name"], "Signal-Glow Grid Model")
        self.assertIn("patterns travel", F4_MODULE_DOC["anchor_sentence"].lower())
        self.assertIn("waves and vibrations", focus)
        self.assertIn("reflection and refraction qualitatively", focus)
        self.assertIn("magnetic effects of current", focus)
        self.assertIn("sound and light as wave phenomena", description)
        self.assertIn("simple circuits", description)
        self.assertIn("series and parallel", mastery_text)

    def test_f5_matches_refined_curriculum_identity(self) -> None:
        description = str(F5_MODULE_DOC.get("description") or F5_MODULE_DOC.get("module_description") or "").lower()
        mastery_text = " ".join(F5_MODULE_DOC.get("mastery_outcomes") or []).lower()
        focus = " ".join(F5_MODULE_DOC.get("curriculum_focus") or []).lower()

        self.assertEqual(F5_MODULE_DOC["title"], "Observable Earth and Sky")
        self.assertEqual(F5_MODULE_DOC["analogy_model_name"], "Lantern-Ring Skycourt Model")
        self.assertIn("earth spins for day and night", F5_MODULE_DOC["anchor_sentence"].lower())
        self.assertIn("phases of the moon", focus)
        self.assertIn("scale of earth, sun, and planets", focus)
        self.assertIn("solar system", mastery_text)
        self.assertIn("seasons", description)


if __name__ == "__main__":
    unittest.main()
