from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List

# Make repo root importable when script is run directly from /scripts
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from google.cloud import firestore  # type: ignore

from app.db.firestore import get_firestore_client


def chunked(items: List[Any], size: int) -> List[List[Any]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def list_matching_progress_events(
    db: firestore.Client,
    uid: str,
    module_id: str,
) -> List[firestore.DocumentSnapshot]:
    matches: List[firestore.DocumentSnapshot] = []

    # Query by uid first, then filter module_id in memory if composite index is absent.
    query = db.collection("progress_events").where("uid", "==", uid)
    for snap in query.stream():
        data = snap.to_dict() or {}
        if str(data.get("module_id") or "") == module_id:
            matches.append(snap)

    return matches


def reset_user_module_progress(
    uid: str,
    module_id: str,
    dry_run: bool = False,
) -> Dict[str, Any]:
    db = get_firestore_client()

    module_ref = (
        db.collection("progress")
        .document(uid)
        .collection("modules")
        .document(module_id)
    )

    module_snap = module_ref.get()
    event_snaps = list_matching_progress_events(db=db, uid=uid, module_id=module_id)

    progress_root_ref = db.collection("progress").document(uid)
    progress_root_snap = progress_root_ref.get()
    progress_root_exists = progress_root_snap.exists

    result: Dict[str, Any] = {
        "uid": uid,
        "module_id": module_id,
        "module_progress_exists": module_snap.exists,
        "progress_root_exists": progress_root_exists,
        "matching_progress_events": len(event_snaps),
        "deleted_module_progress": False,
        "deleted_progress_events": 0,
        "dry_run": dry_run,
    }

    if dry_run:
        return result

    if module_snap.exists:
        module_ref.delete()
        result["deleted_module_progress"] = True

    deleted_events = 0
    for batch_snaps in chunked(event_snaps, 400):
        batch = db.batch()
        for snap in batch_snaps:
            batch.delete(snap.reference)
        batch.commit()
        deleted_events += len(batch_snaps)

    result["deleted_progress_events"] = deleted_events

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reset persisted progress for one user and one module."
    )
    parser.add_argument("--uid", required=True, help="Firebase Auth UID")
    parser.add_argument("--module", required=True, help="Module ID, e.g. F1")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Inspect what would be deleted without deleting anything.",
    )
    args = parser.parse_args()

    payload = reset_user_module_progress(
        uid=str(args.uid).strip(),
        module_id=str(args.module).strip(),
        dry_run=bool(args.dry_run),
    )
    print(payload)


if __name__ == "__main__":
    main()