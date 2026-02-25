import time
from datetime import datetime, timezone, timedelta
from typing import Tuple, Dict, Any
from google.cloud import firestore

db = firestore.Client()

# === AUTO-DISABLE THRESHOLDS ===
WINDOW_VIOLATION_THRESHOLD_PER_HOUR = 50
DAILY_VIOLATION_THRESHOLD_PER_24H = 5

def _now():
    return datetime.now(timezone.utc)

def _utc_midnight():
    now = _now()
    return datetime(now.year, now.month, now.day, tzinfo=timezone.utc)

def _epoch(dt: datetime):
    return int(dt.timestamp())

def _ttl_30_days():
    return _now() + timedelta(days=30)

def enforce_rate_limit(key_id: str, policy: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    now = _now()

    window_limit = policy.get("rl_window_limit", 10)
    window_seconds = policy.get("rl_window_seconds", 60)
    bucket_seconds = policy.get("rl_bucket_seconds", 10)
    daily_limit = policy.get("rl_daily_limit", 1000)

    window_start = int(time.time() // bucket_seconds) * bucket_seconds
    daily_start = _utc_midnight()

    window_doc = db.collection("rate_limit_window").document(f"{key_id}_{window_start}")
    daily_doc = db.collection("rate_limit_daily").document(f"{key_id}_{daily_start.date()}")

    window_snapshot = window_doc.get()
    daily_snapshot = daily_doc.get()

    window_count = window_snapshot.to_dict().get("count", 0) if window_snapshot.exists else 0
    daily_count = daily_snapshot.to_dict().get("count", 0) if daily_snapshot.exists else 0

    # === WINDOW LIMIT ===
    if window_count >= window_limit:
        retry_after = window_start + bucket_seconds - int(time.time())
        log_violation(key_id, "api_key.rate_limited.window")
        check_auto_disable(key_id)
        return False, {
            "type": "window",
            "retry_after": max(retry_after, 1),
            "window_remaining": 0,
            "daily_remaining": max(daily_limit - daily_count, 0),
            "window_reset": window_start + bucket_seconds,
            "daily_reset": _epoch(daily_start + timedelta(days=1)),
        }

    # === DAILY LIMIT ===
    if daily_count >= daily_limit:
        retry_after = _epoch(daily_start + timedelta(days=1)) - int(time.time())
        log_violation(key_id, "api_key.rate_limited.daily")
        check_auto_disable(key_id)
        return False, {
            "type": "daily",
            "retry_after": max(retry_after, 1),
            "window_remaining": max(window_limit - window_count, 0),
            "daily_remaining": 0,
            "window_reset": window_start + bucket_seconds,
            "daily_reset": _epoch(daily_start + timedelta(days=1)),
        }

    # === INCREMENT COUNTERS ===
    window_doc.set({"count": firestore.Increment(1)}, merge=True)
    daily_doc.set({"count": firestore.Increment(1)}, merge=True)

    return True, {
        "window_remaining": window_limit - (window_count + 1),
        "daily_remaining": daily_limit - (daily_count + 1),
        "window_reset": window_start + bucket_seconds,
        "daily_reset": _epoch(daily_start + timedelta(days=1)),
    }


def log_violation(key_id: str, event_type: str):
    db.collection("audit_logs").add({
        "key_id": key_id,
        "event_type": event_type,
        "ts": _now(),
        "expires_at_utc": _ttl_30_days(),
    })


def check_auto_disable(key_id: str):
    one_hour_ago = _now() - timedelta(hours=1)
    one_day_ago = _now() - timedelta(hours=24)

    window_violations = (
        db.collection_group("audit_logs")
        .where("key_id", "==", key_id)
        .where("event_type", "==", "api_key.rate_limited.window")
        .where("ts", ">=", one_hour_ago)
        .get()
    )

    daily_violations = (
        db.collection_group("audit_logs")
        .where("key_id", "==", key_id)
        .where("event_type", "==", "api_key.rate_limited.daily")
        .where("ts", ">=", one_day_ago)
        .get()
    )

    if len(window_violations) > WINDOW_VIOLATION_THRESHOLD_PER_HOUR or \
       len(daily_violations) > DAILY_VIOLATION_THRESHOLD_PER_24H:

        db.collection("keys").document(key_id).update({
            "active": False,
            "disabled_reason": "abuse_threshold",
            "disabled_at_utc": _now(),
        })

        db.collection("audit_logs").add({
            "key_id": key_id,
            "event_type": "api_key.auto_disabled",
            "ts": _now(),
            "expires_at_utc": _ttl_30_days(),
        })