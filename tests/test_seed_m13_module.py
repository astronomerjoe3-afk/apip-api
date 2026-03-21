import unittest

from scripts.seed_m13_module import M13_LESSONS, M13_MODULE_DOC, M13_SIM_LABS


class SeedM13ModuleTests(unittest.TestCase):
    def test_bundle_has_expected_module_shape(self) -> None:
        self.assertEqual(M13_MODULE_DOC["module_id"], "M13")
        self.assertEqual(M13_MODULE_DOC["title"], "Radioactivity")
        self.assertEqual(len(M13_LESSONS), 6)
        self.assertEqual(len(M13_SIM_LABS), 6)

    def test_lessons_cover_all_core_vault_topics(self) -> None:
        lesson_ids = [lesson_id for lesson_id, _ in M13_LESSONS]
        self.assertEqual(
            lesson_ids,
            ["M13_L1", "M13_L2", "M13_L3", "M13_L4", "M13_L5", "M13_L6"],
        )

        authored_concepts = [
            lesson["authoring_contract"]["simulation_contract"]["concept"]
            for _, lesson in M13_LESSONS
        ]
        self.assertEqual(
            authored_concepts,
            [
                "core_vault_identity",
                "same_badge_vaults",
                "escape_signals",
                "settle_span",
                "ambient_buzz",
                "vault_ledger",
            ],
        )


if __name__ == "__main__":
    unittest.main()
