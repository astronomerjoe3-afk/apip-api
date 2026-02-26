from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, Tuple

from google.cloud import firestore


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def safe_int(x: Any, default: int = 0) -> int:
    try:
        if x is None:
            return default
        return int(x)
    except Exception:
        return default


def day_key(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d")


def ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b


@dataclass
class RLMeta:
    window_remaining: int
    window_reset: int
    daily_remaining: int
    daily_reset: int
    retry_after: Optional[int] = None
    violation: Optional[str] = None   # "window" | "daily"
    auto_disabled: bool = False


def enforce_rate_limit(*, db: firestore.Client, key_id: str, policy: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    """
    Firestore-backed rate limiting with:
    - per-key rolling window counter (fixed window)
    - per-key daily counter
    - per-key abuse TTL counters (1h + 24h) for metrics/top keys + auto-disable
    - global abuse TTL counters (1h + 24h) for posture metrics

    IMPORTANT:
    - Transaction reads are performed before writes (so 429 never becomes 500 due to ordering).
    """

    # Policy defaults
    window_limit = safe_int(policy.get("rl_window_limit", 10), 10)
    window_seconds = safe_int(policy.get("rl_window_seconds", 60), 60)
    daily_limit = safe_int(policy.get("rl_daily_limit", 1000), 1000)

    # Bucket seconds is kept for future smoothing; current impl uses fixed window.
    # (We keep the field so existing keys remain valid.)
    _bucket_seconds = safe_int(policy.get("rl_bucket_seconds", 10), 10)

    # Auto-disable thresholds (abuse events) - safe defaults
    # If you store these on the key doc, they apply per key.
    auto_disable_1h = safe_int(policy.get("auto_disable_1h", 50), 50)
    auto_disable_24h = safe_int(policy.get("auto_disable_24h", 200), 200)

    ts = now_utc()

    # Reset timestamps (epoch seconds)
    current_window_start = int(ts.timestamp() // window_seconds) * window_seconds
    window_reset = current_window_start + window_seconds
    daily_reset_dt = datetime(ts.year, ts.month, ts.day, tzinfo=timezone.utc) + timedelta(days=1)
    daily_reset = int(daily_reset_dt.timestamp())

    rl_state_ref = db.collection("rl_state").document(key_id)

    abuse_1h_ref = db.collection("api_key_abuse_1h").document(key_id)
    abuse_24h_ref = db.collection("api_key_abuse_24h").document(key_id)

    global_1h_ref = db.collection("global_abuse_1h").document("global")
    global_24h_ref = db.collection("global_abuse_24h").document("global")

    keys_ref = db.collection("keys").document(key_id)

    def _ttl(hours: int) -> datetime:
        return ts + timedelta(hours=hours)

    meta = RLMeta(
        window_remaining=window_limit,
        window_reset=window_reset,
        daily_remaining=daily_limit,
        daily_reset=daily_reset,
    )

    @firestore.transactional
    def txn_body(txn: firestore.Transaction) -> Tuple[bool, RLMeta]:
        # ---- READS (must come first) ----
        rl_snap = rl_state_ref.get(transaction=txn)
        abuse1_snap = abuse_1h_ref.get(transaction=txn)
        abuse24_snap = abuse_24h_ref.get(transaction=txn)
        g1_snap = global_1h_ref.get(transaction=txn)
        g24_snap = global_24h_ref.get(transaction=txn)
        key_snap = keys_ref.get(transaction=txn)

        # Key might be disabled asynchronously
        if not key_snap.exists:
            meta.violation = "window"
            meta.retry_after = 1
            return False, meta

        key_doc = key_snap.to_dict() or {}
        if not key_doc.get("active", False):
            meta.violation = "window"
            meta.retry_after = 1
            return False, meta

        rl = rl_snap.to_dict() if rl_snap.exists else {}
        window_start = safe_int(rl.get("window_start", current_window_start), current_window_start)
        window_count = safe_int(rl.get("window_count", 0), 0)

        dkey = day_key(ts)
        daily_key_saved = rl.get("daily_key", dkey)
        daily_count = safe_int(rl.get("daily_count", 0), 0)

        # If window rolled, reset
        if window_start != current_window_start:
            window_start = current_window_start
            window_count = 0

        # If day rolled, reset
        if daily_key_saved != dkey:
            daily_key_saved = dkey
            daily_count = 0

        # Compute allow/deny *before* mutating
        will_window = window_count + 1
        will_daily = daily_count + 1

        window_ok = (will_window <= window_limit)
        daily_ok = (will_daily <= daily_limit)

        # Update remaining counters for response
        meta.window_remaining = max(0, window_limit - will_window)
        meta.daily_remaining = max(0, daily_limit - will_daily)

        # ---- WRITES ----
        # Always write updated rl_state (even on violation, so counters reflect abuse)
        txn.set(rl_state_ref, {
            "key_id": key_id,
            "window_start": window_start,
            "window_count": will_window if window_ok else window_count,  # only increment if allowed
            "daily_key": daily_key_saved,
            "daily_count": will_daily if daily_ok else daily_count,      # only increment if allowed
            "updated_at_utc": ts,
        }, merge=True)

        if window_ok and daily_ok:
            # Allowed
            return True, meta

        # Violation path
        meta.violation = "daily" if (window_ok and not daily_ok) else "window"

        # Retry-after until window reset (or daily reset if daily violation only)
        if meta.violation == "daily":
            meta.retry_after = max(1, daily_reset - int(ts.timestamp()))
        else:
            meta.retry_after = max(1, window_reset - int(ts.timestamp()))

        # Per-key abuse increments (TTL docs for fast metrics)
        def _inc(ref: firestore.DocumentReference, snap, ttl_hours: int):
            if snap.exists:
                txn.set(ref, {
                    "count": firestore.Increment(1),
                    "updated_at_utc": ts,
                    "expires_at_utc": _ttl(ttl_hours),
                }, merge=True)
            else:
                txn.set(ref, {
                    "count": 1,
                    "created_at_utc": ts,
                    "updated_at_utc": ts,
                    "expires_at_utc": _ttl(ttl_hours),
                }, merge=True)

        # Global abuse increments
        _inc(global_1h_ref, g1_snap, ttl_hours=2)
        _inc(global_24h_ref, g24_snap, ttl_hours=30)

        # Key abuse increments
        _inc(abuse_1h_ref, abuse1_snap, ttl_hours=2)
        _inc(abuse_24h_ref, abuse24_snap, ttl_hours=30)

        # Auto-disable evaluation (based on *current* + this increment is approximate)
        # We use snap counts; after increment, real count may be +1. That's fine for thresholding.
        abuse1 = safe_int((abuse1_snap.to_dict() or {}).get("count", 0), 0) + 1
        abuse24 = safe_int((abuse24_snap.to_dict() or {}).get("count", 0), 0) + 1

        should_disable = (abuse1 >= auto_disable_1h) or (abuse24 >= auto_disable_24h)
        if should_disable and key_doc.get("active", True):
            txn.set(keys_ref, {
                "active": False,
                "auto_disabled": True,
                "auto_disabled_at_utc": ts,
                "auto_disabled_reason": f"abuse_threshold:{abuse1}1h/{auto_disable_1h}, {abuse24}24h/{auto_disable_24h}",
                "updated_at_utc": ts,
            }, merge=True)
            meta.auto_disabled = True

        return False, meta

    txn = db.transaction()
    allowed, meta_obj = txn_body(txn)

    return allowed, {
        "window_remaining": meta_obj.window_remaining,
        "window_reset": meta_obj.window_reset,
        "daily_remaining": meta_obj.daily_remaining,
        "daily_reset": meta_obj.daily_reset,
        "retry_after": meta_obj.retry_after,
        "violation": meta_obj.violation,
        "auto_disabled": meta_obj.auto_disabled,
    }
