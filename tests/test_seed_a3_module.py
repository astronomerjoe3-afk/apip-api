import unittest

from scripts.seed_a3_module import A3_LESSONS, A3_MODULE_DOC, A3_SIM_LABS


class SeedA3ModuleTests(unittest.TestCase):
    def test_bundle_has_expected_module_shape(self) -> None:
        self.assertEqual(A3_MODULE_DOC["module_id"], "A3")
        self.assertEqual(A3_MODULE_DOC["title"], "Fields & Electromagnetic Theory")
        self.assertEqual(len(A3_LESSONS), 6)
        self.assertEqual(len(A3_SIM_LABS), 6)

    def test_lessons_cover_thread_window_scope(self) -> None:
        lesson_ids = [lesson_id for lesson_id, _ in A3_LESSONS]
        self.assertEqual(
            lesson_ids,
            ["A3_L1", "A3_L2", "A3_L3", "A3_L4", "A3_L5", "A3_L6"],
        )

        authored_concepts = [
            lesson["authoring_contract"]["simulation_contract"]["concept"]
            for _, lesson in A3_LESSONS
        ]
        self.assertEqual(
            authored_concepts,
            [
                "flux_window",
                "induction_pulse",
                "flux_linkage_coil",
                "lenz_opposition",
                "drive_sorter",
                "heat_match",
            ],
        )


if __name__ == "__main__":
    unittest.main()
