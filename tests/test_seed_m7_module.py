import unittest
from typing import Any, Dict, Iterable

from scripts.seed_m7_module import M7_LESSONS, M7_MODULE_DOC, M7_SIM_LABS


def iter_short_items(node: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(node, list):
        for value in node:
            yield from iter_short_items(value)
        return

    if not isinstance(node, dict):
        return

    kind = str(node.get("kind") or node.get("type") or "").strip().lower()
    if kind == "short":
        yield node

    for value in node.values():
        yield from iter_short_items(value)


class SeedM7ModuleTests(unittest.TestCase):
    def test_bundle_has_expected_module_shape(self) -> None:
        self.assertEqual(M7_MODULE_DOC["module_id"], "M7")
        self.assertEqual(M7_MODULE_DOC["title"], "Waves and Vibrations")
        self.assertEqual(len(M7_LESSONS), 6)
        self.assertEqual(len(M7_SIM_LABS), 6)

    def test_short_answer_keys_do_not_start_with_because(self) -> None:
        short_items = list(iter_short_items([lesson for _, lesson in M7_LESSONS]))
        self.assertGreater(len(short_items), 0)

        for item in short_items:
            for accepted_answer in item.get("accepted_answers") or []:
                self.assertFalse(
                    str(accepted_answer).lower().startswith("because "),
                    f"{item.get('id')} still starts with 'Because': {accepted_answer}",
                )

    def test_equal_angle_rule_stays_statement_shaped(self) -> None:
        short_items = {
            str(item.get("id")): item
            for item in iter_short_items([lesson for _, lesson in M7_LESSONS])
        }
        self.assertEqual(
            short_items["M7L4_D3"]["accepted_answers"][0],
            "The angle of incidence equals the angle of reflection.",
        )


if __name__ == "__main__":
    unittest.main()
