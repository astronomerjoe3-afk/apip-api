import unittest

from scripts.seed_a4_module import A4_LESSONS, A4_MODULE_DOC, A4_SIM_LABS


class SeedA4ModuleTests(unittest.TestCase):
    def test_bundle_has_expected_module_shape(self) -> None:
        self.assertEqual(A4_MODULE_DOC["module_id"], "A4")
        self.assertEqual(A4_MODULE_DOC["title"], "Thermal & Statistical Physics")
        self.assertEqual(len(A4_LESSONS), 6)
        self.assertEqual(len(A4_SIM_LABS), 6)

    def test_lessons_cover_bounce_chamber_scope(self) -> None:
        lesson_ids = [lesson_id for lesson_id, _ in A4_LESSONS]
        self.assertEqual(
            lesson_ids,
            ["A4_L1", "A4_L2", "A4_L3", "A4_L4", "A4_L5", "A4_L6"],
        )

        authored_concepts = [
            lesson["authoring_contract"]["simulation_contract"]["concept"]
            for _, lesson in A4_LESSONS
        ]
        self.assertEqual(
            authored_concepts,
            [
                "bounce_chamber_pressure",
                "gas_law_balance",
                "kinetic_theory_bridge",
                "average_dash_energy",
                "partition_expansion",
                "entropy_option_count",
            ],
        )


if __name__ == "__main__":
    unittest.main()
