from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Sequence, Tuple

from lesson_authoring_contract import (
    LessonAuthoringContractError,
    clone_template,
    nextgen_lesson_template,
    nextgen_module_doc_template,
    validate_nextgen_module,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_nextgen_module_scaffold(
    module_id: str,
    title: str,
    description: str,
    lesson_titles: Sequence[str],
    allowlist: Sequence[str],
    *,
    sequence: int = 4,
    level: str = "Advanced Foundation",
    estimated_minutes: int = 120,
) -> Tuple[Dict[str, object], List[Dict[str, object]], List[Dict[str, object]]]:
    module_doc = clone_template(nextgen_module_doc_template(module_id, title, description, allowlist))
    module_doc["sequence"] = sequence
    module_doc["level"] = level
    module_doc["estimated_minutes"] = estimated_minutes
    module_doc["updated_utc"] = utc_now()

    lessons: List[Dict[str, object]] = []
    sim_labs: List[Dict[str, object]] = []
    for index, lesson_title in enumerate(lesson_titles, start=1):
        lesson_id = f"{module_id}_L{index}"
        lesson = clone_template(nextgen_lesson_template(module_id, lesson_id, index, lesson_title))
        lesson["updated_utc"] = utc_now()
        lessons.append(lesson)
        sim_labs.append(
            {
                "lab_id": f"{lesson_id.lower()}_lab",
                "module_id": module_id,
                "title": f"{lesson_title} explorer",
                "description": "Replace with a simulation or investigation brief.",
                "instructions": [
                    "Replace with a baseline test case.",
                    "Replace with a compare-two-cases instruction.",
                    "Replace with an explanation prompt tied to the core idea.",
                ],
            }
        )
    return module_doc, lessons, sim_labs


EXAMPLE_ALLOWLIST = [
    "replace_me_primary_confusion",
    "replace_me_secondary_confusion",
    "replace_me_graph_reasoning_confusion",
]

EXAMPLE_LESSON_TITLES = [
    "Lesson 1 placeholder",
    "Lesson 2 placeholder",
    "Lesson 3 placeholder",
    "Lesson 4 placeholder",
    "Lesson 5 placeholder",
    "Lesson 6 placeholder",
]


if __name__ == "__main__":
    module_doc, lessons, sim_labs = build_nextgen_module_scaffold(
        "F4",
        "Replace with approved F4 title",
        "Replace with approved F4 description.",
        EXAMPLE_LESSON_TITLES,
        EXAMPLE_ALLOWLIST,
    )
    print(f"Scaffolded {module_doc['module_id']} with {len(lessons)} placeholder lessons.")
    try:
        validate_nextgen_module(module_doc, lessons, sim_labs, EXAMPLE_ALLOWLIST)
        print("Validation passed.")
    except LessonAuthoringContractError as exc:
        print("Validation is expected to fail until the placeholders are replaced with real content.")
        print(exc)
