import unittest

from scripts.seed_m14_module import M14_LESSONS, M14_MODULE_DOC, M14_SIM_LABS


class SeedM14ModuleTests(unittest.TestCase):
    def test_bundle_has_expected_module_shape(self) -> None:
        self.assertEqual(M14_MODULE_DOC["module_id"], "M14")
        self.assertEqual(M14_MODULE_DOC["title"], "Solar System")
        self.assertEqual(len(M14_LESSONS), 6)
        self.assertEqual(len(M14_SIM_LABS), 6)

    def test_lessons_cover_lantern_ring_scope(self) -> None:
        lesson_ids = [lesson_id for lesson_id, _ in M14_LESSONS]
        self.assertEqual(
            lesson_ids,
            ["M14_L1", "M14_L2", "M14_L3", "M14_L4", "M14_L5", "M14_L6"],
        )

        authored_concepts = [
            lesson["authoring_contract"]["simulation_contract"]["concept"]
            for _, lesson in M14_LESSONS
        ]
        self.assertEqual(
            authored_concepts,
            [
                "solar_court_sort",
                "hub_pull_routes",
                "spin_for_daylight",
                "season_switch",
                "moon_face_challenge",
                "outer_lap_puzzle",
            ],
        )


if __name__ == "__main__":
    unittest.main()
