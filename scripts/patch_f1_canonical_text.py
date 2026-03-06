from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Dict, Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.db.firestore import get_firestore_client


CANONICAL_PATCHES: Dict[str, Dict[str, Any]] = {
    "F1_L1": {
        "phases": {
            "analogical_grounding": {
                "analogy_text": "Think of units like currency: you can't meaningfully add 'dollars' to 'meters'—and you can't pay with 'kilo-' without converting. Prefixes are like denominations (cents, dollars, thousands). Good physics starts by keeping the 'currency' consistent."
            }
        }
    },
    "F1_L2": {
        "phases": {
            "analogical_grounding": {
                "analogy_text": "A scalar is like a thermometer reading—only a size. A vector is like a walking instruction—size plus direction. Confusing them is like saying 'walk 5' without telling where."
            }
        }
    },
    "F1_L3": {
        "phases": {
            "analogical_grounding": {
                "analogy_text": "Reading a scale is like reading a map grid: your precision is limited by the smallest division. If the ruler has millimeter marks, pretending you know micrometers is inventing information."
            },
            "diagnostic": {
                "items": [
                    {
                        "type": "mcq",
                        "prompt": "A ruler's smallest division is 1 mm. A reasonable reported uncertainty is closest to:",
                        "choices": ["±1 mm", "±0.5 mm", "±0.1 mm", "±2 mm"],
                        "question_id": "F1L3_D1",
                        "correct_index": 1,
                        "misconception_tags": ["reading_scales", "uncertainty_estimation"],
                    },
                    {
                        "type": "mcq",
                        "prompt": "If you consistently read too high due to a zero error, this is best described as:",
                        "choices": ["random error", "systematic error", "no error", "rounding error only"],
                        "question_id": "F1L3_D2",
                        "correct_index": 1,
                        "misconception_tags": ["random_vs_systematic_error"],
                    },
                ]
            }
        }
    },
    "F1_L4": {
        "phases": {
            "analogical_grounding": {
                "analogy_text": "Significant figures are honesty rules for numbers. If your measurement is rough, your final answer must be rough too. Reporting extra digits is like adding fake detail to a blurry photo."
            }
        }
    },
    "F1_L5": {
        "phases": {
            "analogical_grounding": {
                "analogy_text": "Density is how tightly packed matter is—like how crowded a room is: people per square meter. In physics, it is mass per volume, and units matter (kg/m^3 vs g/cm^3)."
            },
            "diagnostic": {
                "items": [
                    {
                        "type": "mcq",
                        "prompt": "Density is defined as:",
                        "choices": ["mass × volume", "mass ÷ volume", "volume ÷ mass", "mass + volume"],
                        "question_id": "F1L5_D1",
                        "correct_index": 1,
                        "misconception_tags": ["density_concept"],
                    },
                    {
                        "type": "mcq",
                        "prompt": "Which unit is appropriate for density?",
                        "choices": ["kg", "m^3", "kg/m^3", "N"],
                        "question_id": "F1L5_D2",
                        "correct_index": 2,
                        "misconception_tags": ["density_units"],
                    },
                ]
            }
        }
    },
    "F1_L6": {
        "phases": {
            "transfer": {
                "items": [
                    {
                        "type": "short",
                        "prompt": "You measure length as 12.4 cm with a ruler of 1 mm divisions. Report the value with a reasonable uncertainty.",
                        "question_id": "F1L6_T1",
                        "misconception_tags": ["uncertainty_estimation", "reading_scales"],
                    },
                    {
                        "type": "short",
                        "prompt": "In 2–3 sentences, explain the difference between precision and accuracy using an example.",
                        "question_id": "F1L6_T2",
                        "misconception_tags": ["precision_vs_accuracy"],
                    },
                ]
            },
            "analogical_grounding": {
                "analogy_text": "Precision is how tightly your shots group; accuracy is whether the group hits the bullseye. Uncertainty is your honest estimate of how wide the group could be given your instrument and method."
            }
        }
    },
}


def deep_merge(base: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def main() -> None:
    project = (
        os.getenv("GOOGLE_CLOUD_PROJECT")
        or os.getenv("GCP_PROJECT")
        or os.getenv("GCLOUD_PROJECT")
        or "(auto)"
    )

    db = get_firestore_client()
    updated = 0

    for lesson_id, patch in CANONICAL_PATCHES.items():
        top_ref = db.collection("lessons").document(lesson_id)
        snap = top_ref.get()
        if not snap.exists:
            print(f"[SKIP] lessons/{lesson_id} not found")
            continue

        current = snap.to_dict() or {}
        merged = deep_merge(current, patch)
        top_ref.set(merged, merge=False)
        print(f"[UPDATED] lessons/{lesson_id}")

        legacy_ref = db.collection("modules").document("F1").collection("lessons").document(lesson_id)
        if legacy_ref.get().exists:
            legacy_ref.set(merged, merge=False)
            print(f"[UPDATED] modules/F1/lessons/{lesson_id}")

        updated += 1

    print(
        {
            "project": project,
            "module_id": "F1",
            "patched_lessons": updated,
        }
    )


if __name__ == "__main__":
    main()
