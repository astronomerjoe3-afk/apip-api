import unittest
from typing import Any, Dict, Iterable

from scripts.seed_m8_module import M8_LESSONS, M8_MODULE_DOC, M8_SIM_LABS


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


class SeedM8ModuleTests(unittest.TestCase):
    def test_bundle_has_expected_module_shape(self) -> None:
        self.assertEqual(M8_MODULE_DOC["module_id"], "M8")
        self.assertEqual(M8_MODULE_DOC["title"], "Light and Optics")
        self.assertEqual(len(M8_LESSONS), 6)
        self.assertEqual(len(M8_SIM_LABS), 6)

    def test_short_answer_keys_do_not_start_with_because(self) -> None:
        short_items = list(iter_short_items([lesson for _, lesson in M8_LESSONS]))
        self.assertGreater(len(short_items), 0)

        for item in short_items:
            for accepted_answer in item.get("accepted_answers") or []:
                self.assertFalse(
                    str(accepted_answer).lower().startswith("because "),
                    f"{item.get('id')} still starts with 'Because': {accepted_answer}",
                )

    def test_m8_l2_short_answers_use_sharper_direction_plus_reason_wording(self) -> None:
        short_items = {
            str(item.get("id")): item
            for item in iter_short_items([lesson for _, lesson in M8_LESSONS])
        }

        self.assertEqual(
            short_items["M8L2_C8"]["accepted_answers"][0],
            "The route bends away from the Guide Line because the new medium is faster.",
        )
        self.assertEqual(
            short_items["M8L2_M9"]["accepted_answers"][0],
            "Less than 60 degrees: entering a slower medium bends the route toward the Guide Line.",
        )


if __name__ == "__main__":
    unittest.main()
