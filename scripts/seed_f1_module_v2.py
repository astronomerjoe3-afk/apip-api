import json
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Set

import firebase_admin
from firebase_admin import firestore

# ---------------------------
# Utilities
# ---------------------------

def stable_hash(obj: Any) -> str:
    """Deterministic short hash for content versioning (journal-grade reproducibility)."""
    raw = json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]

def now_iso() -> str:
    # timezone-aware UTC (avoids DeprecationWarning)
    return datetime.now(timezone.utc).isoformat()

def ensure_unique_ids(lesson_id: str, *lists: List[Dict[str, Any]]) -> None:
    seen: Set[str] = set()
    for lst in lists:
        for item in lst:
            iid = item.get("id")
            if not iid:
                raise ValueError(f"[{lesson_id}] Missing item.id: {item}")
            if iid in seen:
                raise ValueError(f"[{lesson_id}] Duplicate item.id detected: {iid}")
            seen.add(iid)

def ensure_student_safe_item(item: Dict[str, Any]) -> None:
    """
    Student UI constraints:
    - Only prompt/tasks/hints/feedback/grades visible.
    - No internal tags/labels should appear in student-visible strings.
    We enforce minimal required fields for rendering and scoring.
    """
    required = ["id", "prompt", "choices", "answer_index", "hint", "feedback"]
    missing = [k for k in required if k not in item]
    if missing:
        raise ValueError(f"Item missing fields {missing}: {item}")
    if not isinstance(item["choices"], list) or len(item["choices"]) < 2:
        raise ValueError(f"Item choices invalid: {item.get('id')}")
    if not isinstance(item["feedback"], list) or len(item["feedback"]) != len(item["choices"]):
        raise ValueError(f"Item feedback must match choices length: {item.get('id')}")
    if not isinstance(item["answer_index"], int) or not (0 <= item["answer_index"] < len(item["choices"])):
        raise ValueError(f"Item answer_index out of range: {item.get('id')}")

# ---------------------------
# Content: Module + Lessons
# ---------------------------

MODULE_ID = "F1"

def module_doc() -> Dict[str, Any]:
    return {
        "id": MODULE_ID,
        "title": "Physical Quantities & Measurement",
        "level": 1,
        "order": 1,
        "active": True,
        "lessonIds": ["F1-L1", "F1-L2", "F1-L3", "F1-L4"],
        "createdAt": firestore.SERVER_TIMESTAMP,
        "updatedAt": firestore.SERVER_TIMESTAMP,
    }

def lesson_f1_l1() -> Dict[str, Any]:
    """
    L1: SI units + complete measurement concept
    """
    diag = [
        {
            "id": "F1-L1-D1",
            "prompt": "Which pair correctly matches quantity to SI unit?",
            "choices": ["mass → m", "length → m", "time → kg", "temperature → s"],
            "answer_index": 1,
            "hint": "Metre (m) is for length.",
            "feedback": ["No.", "Correct.", "No.", "No."]
        },
        {
            "id": "F1-L1-D2",
            "prompt": "Which is the SI base unit for mass?",
            "choices": ["gram (g)", "kilogram (kg)", "newton (N)", "metre (m)"],
            "answer_index": 1,
            "hint": "Base unit is kg.",
            "feedback": ["No.", "Correct.", "No.", "No."]
        }
    ]

    transfer = [
        {
            "id": "F1-L1-T1",
            "prompt": "A student records '25' for the length of a table. What is the scientific problem with this result?",
            "choices": ["The number is too small", "No unit is given", "The table is too long", "It should be in kilograms"],
            "answer_index": 1,
            "hint": "A measurement must include a unit.",
            "feedback": ["No.", "Correct.", "No.", "No."]
        }
    ]

    capsule_checks = [
        {
            "id": "F1-L1-C1",
            "prompt": "Which is a complete measurement?",
            "choices": ["12", "12 cm", "cm", "length"],
            "answer_index": 1,
            "hint": "Number + unit.",
            "feedback": ["Incomplete.", "Correct.", "Incomplete.", "Not a measurement."]
        }
    ]

    ensure_unique_ids("F1-L1", diag, transfer, capsule_checks)
    for item in diag + transfer + capsule_checks:
        ensure_student_safe_item(item)

    lesson = {
        "id": "F1-L1",
        "moduleId": MODULE_ID,
        "order": 1,
        "title": "SI Units & Complete Measurements",
        "objectiveCodes": ["F1.SI.1", "F1.MEAS.1"],
        "active": True,
        "phases": {
            "analogical_grounding": {
                "analogy_text": (
                    "Think of measurement like a shared language. "
                    "SI units are the agreed vocabulary so your results make sense anywhere."
                ),
                "micro_prompts": [
                    {
                        "prompt": "In one sentence, why do scientists prefer standard units?",
                        "hint": "Think: comparison and communication."
                    }
                ]
            },
            "simulation_inquiry": {
                "lab_id": "F1-PRECISION-LAB-01",
                "lab_once": True,
                "inquiry_prompts": [
                    {"prompt": "Measure the same object 5 times. What changes each time?", "hint": "Look for small variation."},
                    {"prompt": "What does repeated measurement tell you about reliability?", "hint": "Consistency vs noise."}
                ]
            },
            "concept_reconstruction": {
                "capsules": [
                    {
                        "prompt": "Key idea: A measurement must include a value AND a unit.",
                        "checks": [capsule_checks[0]]
                    },
                    {
                        "prompt": "SI base units include m, kg, s, A, K, mol, cd.",
                        "checks": []
                    }
                ]
            },
            "diagnostic": {"items": diag, "dedupe_keyspace": "F1-L1"},
            "transfer": {"items": transfer, "dedupe_keyspace": "F1-L1"}
        },
        "grading": {"completion_threshold": 0.8, "no_repeat_questions": True},
        "telemetry": {"version": 2},
        "createdAt": firestore.SERVER_TIMESTAMP,
        "updatedAt": firestore.SERVER_TIMESTAMP
    }

    hash_basis = {k: v for k, v in lesson.items() if k not in ("createdAt", "updatedAt")}
    lesson["telemetry"]["content_hash"] = stable_hash(hash_basis)
    return lesson

def lesson_f1_l2() -> Dict[str, Any]:
    """
    L2: Scalars vs vectors
    """
    diag = [
        {
            "id": "F1-L2-D1",
            "prompt": "Which quantity is a vector?",
            "choices": ["speed", "distance", "velocity", "mass"],
            "answer_index": 2,
            "hint": "Vector needs direction.",
            "feedback": ["No.", "No.", "Correct.", "No."]
        },
        {
            "id": "F1-L2-D2",
            "prompt": "Which statement is correct?",
            "choices": ["Scalars have direction", "Vectors have magnitude only", "Vectors have magnitude and direction", "Scalars are always negative"],
            "answer_index": 2,
            "hint": "Vector = magnitude + direction.",
            "feedback": ["No.", "No.", "Correct.", "No."]
        }
    ]

    transfer = [
        {
            "id": "F1-L2-T1",
            "prompt": "A car moves 5 km east. Is this a scalar or vector description?",
            "choices": ["Scalar", "Vector", "Neither", "Both"],
            "answer_index": 1,
            "hint": "It includes direction (east).",
            "feedback": ["No.", "Correct.", "No.", "No."]
        }
    ]

    capsule_checks = [
        {
            "id": "F1-L2-C1",
            "prompt": "Which is a scalar quantity?",
            "choices": ["displacement", "velocity", "distance", "force"],
            "answer_index": 2,
            "hint": "No direction needed.",
            "feedback": ["No.", "No.", "Correct.", "No."]
        }
    ]

    ensure_unique_ids("F1-L2", diag, transfer, capsule_checks)
    for item in diag + transfer + capsule_checks:
        ensure_student_safe_item(item)

    lesson = {
        "id": "F1-L2",
        "moduleId": MODULE_ID,
        "order": 2,
        "title": "Scalars vs Vectors",
        "objectiveCodes": ["F1.VEC.1"],
        "active": True,
        "phases": {
            "analogical_grounding": {
                "analogy_text": (
                    "A scalar is like 'how much' (just size). "
                    "A vector is like 'how much AND which way' (size + direction)."
                ),
                "micro_prompts": [
                    {"prompt": "What extra information turns a scalar into a vector?", "hint": "Think: direction."}
                ]
            },
            "simulation_inquiry": {
                "lab_id": "F1-VECTOR-LAB-01",
                "lab_once": True,
                "inquiry_prompts": [
                    {"prompt": "Change only direction while keeping the same magnitude. What changes about the vector?", "hint": "Direction matters."},
                    {"prompt": "Compare distance and displacement for a path with turns.", "hint": "One depends on direction."}
                ]
            },
            "concept_reconstruction": {
                "capsules": [
                    {"prompt": "Scalar: magnitude only. Vector: magnitude + direction.", "checks": [capsule_checks[0]]}
                ]
            },
            "diagnostic": {"items": diag, "dedupe_keyspace": "F1-L2"},
            "transfer": {"items": transfer, "dedupe_keyspace": "F1-L2"}
        },
        "grading": {"completion_threshold": 0.8, "no_repeat_questions": True},
        "telemetry": {"version": 2},
        "createdAt": firestore.SERVER_TIMESTAMP,
        "updatedAt": firestore.SERVER_TIMESTAMP
    }

    hash_basis = {k: v for k, v in lesson.items() if k not in ("createdAt", "updatedAt")}
    lesson["telemetry"]["content_hash"] = stable_hash(hash_basis)
    return lesson

def lesson_f1_l3() -> Dict[str, Any]:
    """
    L3: Density
    """
    diag = [
        {
            "id": "F1-L3-D1",
            "prompt": "Which formula matches density?",
            "choices": ["density = mass × volume", "density = mass ÷ volume", "density = volume ÷ mass", "density = mass + volume"],
            "answer_index": 1,
            "hint": "More mass in same volume means higher density.",
            "feedback": ["No.", "Correct.", "No.", "No."]
        },
        {
            "id": "F1-L3-D2",
            "prompt": "If mass stays the same and volume increases, density will…",
            "choices": ["increase", "decrease", "stay the same", "become negative"],
            "answer_index": 1,
            "hint": "density = mass ÷ volume.",
            "feedback": ["No.", "Correct.", "No.", "No."]
        }
    ]

    transfer = [
        {
            "id": "F1-L3-T1",
            "prompt": "A block has mass 200 g and volume 100 cm³. What is its density?",
            "choices": ["0.5 g/cm³", "2 g/cm³", "20 g/cm³", "300 g/cm³"],
            "answer_index": 1,
            "hint": "density = 200 ÷ 100.",
            "feedback": ["No.", "Correct.", "No.", "No."]
        }
    ]

    capsule_checks = [
        {
            "id": "F1-L3-C1",
            "prompt": "Which unit is commonly used for density?",
            "choices": ["kg", "m/s", "g/cm³", "N"],
            "answer_index": 2,
            "hint": "It is mass per volume.",
            "feedback": ["No.", "No.", "Correct.", "No."]
        }
    ]

    ensure_unique_ids("F1-L3", diag, transfer, capsule_checks)
    for item in diag + transfer + capsule_checks:
        ensure_student_safe_item(item)

    lesson = {
        "id": "F1-L3",
        "moduleId": MODULE_ID,
        "order": 3,
        "title": "Density: Mass per Volume",
        "objectiveCodes": ["F1.DEN.1"],
        "active": True,
        "phases": {
            "analogical_grounding": {
                "analogy_text": (
                    "Density is like 'how tightly packed' something is. "
                    "Same size, more mass → more packed → higher density."
                ),
                "micro_prompts": [
                    {"prompt": "If two objects are the same size, what does higher mass suggest about density?", "hint": "Think: packedness."}
                ]
            },
            "simulation_inquiry": {
                "lab_id": "F1-DENSITY-LAB-01",
                "lab_once": True,
                "inquiry_prompts": [
                    {"prompt": "Keep volume fixed and increase mass. What happens to density?", "hint": "mass ÷ volume."},
                    {"prompt": "Keep mass fixed and increase volume. What happens to density?", "hint": "mass ÷ volume."}
                ]
            },
            "concept_reconstruction": {
                "capsules": [
                    {"prompt": "Density = mass ÷ volume. Units are mass per volume.", "checks": [capsule_checks[0]]}
                ]
            },
            "diagnostic": {"items": diag, "dedupe_keyspace": "F1-L3"},
            "transfer": {"items": transfer, "dedupe_keyspace": "F1-L3"}
        },
        "grading": {"completion_threshold": 0.8, "no_repeat_questions": True},
        "telemetry": {"version": 2},
        "createdAt": firestore.SERVER_TIMESTAMP,
        "updatedAt": firestore.SERVER_TIMESTAMP
    }

    hash_basis = {k: v for k, v in lesson.items() if k not in ("createdAt", "updatedAt")}
    lesson["telemetry"]["content_hash"] = stable_hash(hash_basis)
    return lesson

def lesson_f1_l4() -> Dict[str, Any]:
    """
    L4: Precision/uncertainty intro
    """
    diag = [
        {
            "id": "F1-L4-D1",
            "prompt": "Taking repeated measurements helps you estimate…",
            "choices": ["the true value exactly", "how much measurements vary", "the object's color", "the unit system"],
            "answer_index": 1,
            "hint": "Repeat to see spread/variation.",
            "feedback": ["No.", "Correct.", "No.", "No."]
        },
        {
            "id": "F1-L4-D2",
            "prompt": "Which instrument is likely to give the most precise length reading?",
            "choices": ["ruler with 1 cm divisions", "ruler with 1 mm divisions", "a rope", "your hand span"],
            "answer_index": 1,
            "hint": "Smaller divisions = more precise.",
            "feedback": ["No.", "Correct.", "No.", "No."]
        }
    ]

    transfer = [
        {
            "id": "F1-L4-T1",
            "prompt": "A length is measured as 12.3 cm using a ruler marked in millimetres. What is a reasonable idea about its uncertainty?",
            "choices": ["±5 cm", "±0.5 mm", "±10 m", "No uncertainty exists"],
            "answer_index": 1,
            "hint": "Half the smallest division is a common estimate.",
            "feedback": ["No.", "Correct.", "No.", "No."]
        }
    ]

    capsule_checks = [
        {
            "id": "F1-L4-C1",
            "prompt": "Why do we write measurements to a certain number of significant figures?",
            "choices": ["To make numbers larger", "To show precision of measurement", "To avoid units", "To remove errors completely"],
            "answer_index": 1,
            "hint": "It signals precision.",
            "feedback": ["No.", "Correct.", "No.", "No."]
        }
    ]

    ensure_unique_ids("F1-L4", diag, transfer, capsule_checks)
    for item in diag + transfer + capsule_checks:
        ensure_student_safe_item(item)

    lesson = {
        "id": "F1-L4",
        "moduleId": MODULE_ID,
        "order": 4,
        "title": "Precision, Repeats, and Uncertainty",
        "objectiveCodes": ["F1.UNC.1"],
        "active": True,
        "phases": {
            "analogical_grounding": {
                "analogy_text": (
                    "Measuring is like aiming at a target. "
                    "If results cluster tightly, you are precise. "
                    "Repeats show how wide the cluster is."
                ),
                "micro_prompts": [
                    {"prompt": "If repeated results are close together, what does that suggest?", "hint": "Think: precision."}
                ]
            },
            "simulation_inquiry": {
                "lab_id": "F1-UNCERTAINTY-LAB-01",
                "lab_once": True,
                "inquiry_prompts": [
                    {"prompt": "Take multiple readings of the same length. Is the spread small or large?", "hint": "Compare highest and lowest."},
                    {"prompt": "Try a rough tool and a fine tool. Which produces tighter results?", "hint": "Precision depends on scale."}
                ]
            },
            "concept_reconstruction": {
                "capsules": [
                    {"prompt": "Repeats show variation; smaller scale divisions usually increase precision.", "checks": [capsule_checks[0]]}
                ]
            },
            "diagnostic": {"items": diag, "dedupe_keyspace": "F1-L4"},
            "transfer": {"items": transfer, "dedupe_keyspace": "F1-L4"}
        },
        "grading": {"completion_threshold": 0.8, "no_repeat_questions": True},
        "telemetry": {"version": 2},
        "createdAt": firestore.SERVER_TIMESTAMP,
        "updatedAt": firestore.SERVER_TIMESTAMP
    }

    hash_basis = {k: v for k, v in lesson.items() if k not in ("createdAt", "updatedAt")}
    lesson["telemetry"]["content_hash"] = stable_hash(hash_basis)
    return lesson

def build_lessons() -> List[Dict[str, Any]]:
    lessons = [lesson_f1_l1(), lesson_f1_l2(), lesson_f1_l3(), lesson_f1_l4()]

    # Global module-level uniqueness (optional but aligned with "no repeats")
    global_seen: Set[str] = set()
    for les in lessons:
        # diag + transfer
        for phase_name in ("diagnostic", "transfer"):
            for it in les["phases"][phase_name]["items"]:
                if it["id"] in global_seen:
                    raise ValueError(f"[GLOBAL] Duplicate item id across module: {it['id']}")
                global_seen.add(it["id"])

        # capsule checks
        for cap in les["phases"]["concept_reconstruction"]["capsules"]:
            for it in cap.get("checks", []):
                if it["id"] in global_seen:
                    raise ValueError(f"[GLOBAL] Duplicate item id across module: {it['id']}")
                global_seen.add(it["id"])

    return lessons

# ---------------------------
# Firestore Write
# ---------------------------

def main() -> None:
    if not firebase_admin._apps:
        firebase_admin.initialize_app()  # uses GOOGLE_APPLICATION_CREDENTIALS or ADC

    db = firestore.client()

    # Write module doc
    db.collection("modules").document(MODULE_ID).set(module_doc(), merge=True)

    # Dual-write lessons to BOTH schema locations:
    # 1) modules/{moduleId}/lessons/{lessonId}
    # 2) lessons/{lessonId}
    lessons = build_lessons()
    batch = db.batch()
    for lesson in lessons:
        ref_sub = db.collection("modules").document(MODULE_ID).collection("lessons").document(lesson["id"])
        batch.set(ref_sub, lesson, merge=True)

        ref_top = db.collection("lessons").document(lesson["id"])
        batch.set(ref_top, lesson, merge=True)

    batch.commit()

    print(f"[OK] Seeded modules/{MODULE_ID} with {len(lessons)} lessons at {now_iso()}")

if __name__ == "__main__":
    main()
