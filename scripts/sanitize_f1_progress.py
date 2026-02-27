import os
import argparse
import firebase_admin
from firebase_admin import credentials, firestore

PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "apip-dev-487809-c949c")

F1_ALLOWLIST = {
    "unit_conversion",
    "dimensional_analysis",
    "significant_figures",
    "precision_vs_accuracy",
    "zero_error",
    "parallax_error",
    "reading_scale",
    "least_count",
    "scalar_vs_vector",
}

NON_PERSISTED_EVENT_TYPES = {"attempt", "simulation", "reflection"}


def init_firebase():
    if not firebase_admin._apps:
        firebase_admin.initialize_app(credentials.ApplicationDefault(), {"projectId": PROJECT_ID})


def norm(tag: str) -> str:
    return str(tag).strip().lower().replace(" ", "_")[:64]


def main():
    parser = argparse.ArgumentParser(description="Sanitize F1 misconception tags and optionally delete legacy events")
    parser.add_argument("--apply", action="store_true", help="Apply writes (otherwise dry-run)")
    parser.add_argument("--delete-legacy-events", action="store_true", help="Delete progress_events for F1 where event_type is attempt/simulation/reflection")
    args = parser.parse_args()

    init_firebase()
    db = firestore.client()

    # 1) Sanitize module progress docs
    progress_col = db.collection("progress")
    progress_docs = list(progress_col.stream())

    updated = 0
    scanned = 0

    for p in progress_docs:
        uid = p.id
        mp_ref = progress_col.document(uid).collection("modules").document("F1")
        mp = mp_ref.get()
        if not mp.exists:
            continue

        scanned += 1
        data = mp.to_dict() or {}
        prof = (data.get("misconception_profile") or {})
        tags = prof.get("tags") or {}

        if not isinstance(tags, dict):
            tags = {}

        sanitized = {}
        for k, v in tags.items():
            nk = norm(k)
            if nk not in F1_ALLOWLIST:
                continue
            try:
                fv = float(v)
            except Exception:
                continue
            if fv < 0:
                fv = 0.0
            if fv > 1:
                fv = 1.0
            sanitized[nk] = round(fv, 4)

        if sanitized == tags:
            continue

        updated += 1
        print(f"[F1] uid={uid} sanitize tags: before={list(tags.keys())} after={list(sanitized.keys())}")

        if args.apply:
            mp_ref.set(
                {"misconception_profile": {"tags": sanitized, "updated_utc": firestore.SERVER_TIMESTAMP}},
                merge=True,
            )

    print(f"Module progress sanitized: scanned={scanned}, updated={updated}, apply={args.apply}")

    # 2) Optionally delete legacy per-event docs that shouldn't exist
    if args.delete_legacy_events:
        deleted = 0
        checked = 0
        events = db.collection("progress_events").where("module_id", "==", "F1").stream()

        batch = db.batch()
        ops = 0

        for e in events:
            checked += 1
            d = e.to_dict() or {}
            et = str(d.get("event_type") or "").lower().strip()
            if et in NON_PERSISTED_EVENT_TYPES:
                print(f"[DEL] progress_events/{e.id} event_type={et}")
                if args.apply:
                    batch.delete(e.reference)
                    ops += 1
                    deleted += 1
                    if ops >= 400:
                        batch.commit()
                        batch = db.batch()
                        ops = 0

        if args.apply and ops > 0:
            batch.commit()

        print(f"Legacy events: checked={checked}, deleted={deleted}, apply={args.apply}")


if __name__ == "__main__":
    main()