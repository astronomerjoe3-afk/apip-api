import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, Tuple

from fastapi import HTTPException, Request
from google.cloud import firestore


# =========================
# Collections
# =========================
COL_KEYS = "api_keys"               # existing keys collection
COL_RL = "api_key_rl"               # per-key rate limit counters (buckets + daily)
COL_ABUSE_1H = "api_key_abuse_1h"   # per-key violation counters for last hour (TTL doc)
COL_ABUSE_24H = "api_key_abuse_24h" # per-key violation counters for last 24h (TTL doc)


# =========================
# Defaults / env controls
# =========================
DEFAULT_WINDOW_LIMIT = int(os.getenv("RL_DEFAULT_WINDOW_LIMIT", "60"))
DEFAULT_WINDOW_SECONDS = int(os.getenv("RL_DEFAULT_WINDOW_SECONDS", "60"))
DEFAULT_BUCKET_SECONDS = int(os.getenv("RL_DEFAULT_BUCKET_SECONDS", "10"))
DEFAULT_DAILY_LIMIT = int(os.getenv("RL_DEFAULT_DAILY_LIMIT", "0"))  # 0 => disabled

# Auto-disable thresholds (violations within time windows)
AUTO_DISABLE_1H_THRESHOLD = int(os.getenv("RL_AUTO_DISABLE_1H_THRESHOLD", "30"))
AUTO_DISABLE_24H_THRESHOLD = int(os.getenv("RL_AUTO_DISABLE_24H_THRESHOLD", "200"))

# TTL durations for abuse counter docs
ABUSE_1H_TTL_SECONDS = int(os.getenv("RL_ABUSE_1H_TTL_SECONDS", "3600"))
ABUSE_24H_TTL_SECONDS = int(os.getenv("RL_ABUSE_24H_TTL_SECONDS", str(24 * 3600)))

# TTL durations for rate-limit counters
RL_BUCKET_TTL_SECONDS = int(os.getenv("RL_BUCKET_TTL_SECONDS", "7200"))  # keep buckets ~2h
RL_DAILY_TTL_SECONDS = int(os.getenv("RL_DAILY_TTL_SECONDS", str(3 * 24 * 3600)))  # keep daily ~3d


# =========================
# Helpers
# =========================
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _epoch(dt: datetime) -> int:
    return int(dt.timestamp())


def _day_key(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d")


def _ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b


def _safe_int(v: Any, default: int) -> int:
    try:
        if v is None:
            return default
        return int(v)
    except Exception:
        return default


def _policy_from_key_doc(key_doc: Dict[str, Any]) -> Dict[str, int]:
    """
    Per-key policy overrides (stored on api_keys/{key_id}) fall back to env defaults.
    """
    window_limit = _safe_int(key_doc.get("rl_window_limit"), DEFAULT_WINDOW_LIMIT)
    window_seconds = _safe_int(key_doc.get("rl_window_seconds"), DEFAULT_WINDOW_SECONDS)
    bucket_seconds = _safe_int(key_doc.get("rl_bucket_seconds"), DEFAULT_BUCKET_SECONDS)
    daily_limit = _safe_int(key_doc.get("rl_daily_limit"), DEFAULT_DAILY_LIMIT)

    # Guardrails
    if window_limit <= 0:
        window_limit = DEFAULT_WINDOW_LIMIT
    if window_seconds <= 0:
        window_seconds = DEFAULT_WINDOW_SECONDS
    if bucket_seconds <= 0:
        bucket_seconds = DEFAULT_BUCKET_SECONDS
    if bucket_seconds > window_seconds:
        bucket_seconds = max(1, window_seconds)

    return {
        "window_limit": window_limit,
        "window_seconds": window_seconds,
        "bucket_seconds": bucket_seconds,
        "daily_limit": max(0, daily_limit),
    }


@dataclass
class RLMeta:
    violation_type: Optional[str] = None  # "window" | "daily" | None
    window_limit: int = 0
    window_remaining: int = 0
    window_reset: int = 0

    daily_limit: int = 0
    daily_remaining: Optional[int] = None
    daily_reset: Optional[int] = None

    retry_after: int = 0
    auto_disabled: bool = False


def build_rate_limit_headers(meta: RLMeta) -> Dict[str, str]:
    """
    Standard-ish headers + daily quota.
    """
    headers: Dict[str, str] = {
        "X-RateLimit-Limit": str(meta.window_limit),
        "X-RateLimit-Remaining": str(max(0, meta.window_remaining)),
        "X-RateLimit-Reset": str(meta.window_reset),
        "Retry-After": str(max(0, meta.retry_after)),
    }

    # Daily (optional)
    if meta.daily_limit and meta.daily_limit > 0:
        headers["X-RateLimit-Daily-Limit"] = str(meta.daily_limit)
        headers["X-RateLimit-Daily-Remaining"] = str(max(0, int(meta.daily_remaining or 0)))
        headers["X-RateLimit-Daily-Reset"] = str(int(meta.daily_reset or 0))

    # Violation split + disable signal
    if meta.violation_type:
        headers["X-RateLimit-Violation"] = meta.violation_type
    if meta.auto_disabled:
        headers["X-API-Key-Auto-Disabled"] = "true"

    return headers


# =========================
# Firestore schema (per key)
# =========================
# api_key_rl/{key_id}:
#   buckets: { "<bucket_epoch>": <count> }   (optional large map but OK for low TPS)
#   bucket_expires_at_utc: <dt>              (TTL hint)
#   daily: { "<YYYY-MM-DD>": <count> }
#   daily_expires_at_utc: <dt>               (TTL hint)
#
# api_key_abuse_1h/{key_id}:
#   count_window: <int>
#   count_daily: <int>
#   count_total: <int>
#   expires_at_utc: <dt> (TTL)
#
# api_key_abuse_24h/{key_id}:
#   same fields, TTL 24h


def _abuse_doc_update(violation_type: str) -> Dict[str, Any]:
    """
    Split counts by violation_type + total.
    """
    update: Dict[str, Any] = {
        "count_total": firestore.Increment(1),
        "updated_at_utc": _now(),
    }
    if violation_type == "window":
        update["count_window"] = firestore.Increment(1)
    elif violation_type == "daily":
        update["count_daily"] = firestore.Increment(1)
    else:
        # unknown – count_total is still incremented
        update["count_other"] = firestore.Increment(1)
    return update


def _read_count_field(doc: Optional[Dict[str, Any]], field: str) -> int:
    try:
        return int((doc or {}).get(field) or 0)
    except Exception:
        return 0


def enforce_rate_limit(
    db: firestore.Client,
    request: Request,
    key_id: str,
    key_doc: Dict[str, Any],
) -> Tuple[bool, RLMeta]:
    """
    Deterministic API-key rate limiting using Firestore atomic increments.

    Also implements Step 2.2:
      - violation_type split: window vs daily
      - per-key violation counters (1h + 24h) via TTL docs
      - auto-disable if thresholds exceeded (no audit scan)
    """
    policy = _policy_from_key_doc(key_doc)
    now = _now()

    window_limit = policy["window_limit"]
    window_seconds = policy["window_seconds"]
    bucket_seconds = policy["bucket_seconds"]
    daily_limit = policy["daily_limit"]

    # Compute bucket epoch aligned to bucket_seconds
    now_epoch = _epoch(now)
    bucket_epoch = (now_epoch // bucket_seconds) * bucket_seconds

    # Window reset = end of current window interval aligned to window_seconds
    window_start = (now_epoch // window_seconds) * window_seconds
    window_reset = window_start + window_seconds

    # Daily reset = next UTC midnight
    tomorrow = (now + timedelta(days=1)).date()
    daily_reset_dt = datetime(tomorrow.year, tomorrow.month, tomorrow.day, tzinfo=timezone.utc)
    daily_reset = _epoch(daily_reset_dt)
    day_key = _day_key(now)

    rl_ref = db.collection(COL_RL).document(key_id)
    key_ref = db.collection(COL_KEYS).document(key_id)

    abuse_1h_ref = db.collection(COL_ABUSE_1H).document(key_id)
    abuse_24h_ref = db.collection(COL_ABUSE_24H).document(key_id)

    meta = RLMeta(
        violation_type=None,
        window_limit=window_limit,
        window_remaining=window_limit,
        window_reset=window_reset,
        daily_limit=daily_limit,
        daily_remaining=(daily_limit if daily_limit > 0 else None),
        daily_reset=(daily_reset if daily_limit > 0 else None),
        retry_after=0,
        auto_disabled=False,
    )

    @firestore.transactional
    def _tx(transaction: firestore.Transaction) -> Tuple[bool, RLMeta]:
        # Read current RL doc (counters)
        rl_snap = rl_ref.get(transaction=transaction)
        rl_data = rl_snap.to_dict() if rl_snap.exists else {}

        buckets: Dict[str, Any] = (rl_data.get("buckets") or {})
        daily: Dict[str, Any] = (rl_data.get("daily") or {})

        # Clean-ish: drop old buckets outside window horizon (+ a buffer)
        # (We do this lazily to avoid huge maps.)
        horizon = window_start - (2 * window_seconds)
        buckets_clean: Dict[str, int] = {}
        for k, v in buckets.items():
            try:
                k_int = int(k)
                if k_int >= horizon:
                    buckets_clean[str(k_int)] = int(v)
            except Exception:
                continue

        # Compute window usage across last N buckets
        # Number of buckets in a window:
        buckets_per_window = max(1, _ceil_div(window_seconds, bucket_seconds))
        # Earliest included bucket epoch:
        earliest_bucket = bucket_epoch - (buckets_per_window - 1) * bucket_seconds

        window_used = 0
        for be in range(earliest_bucket, bucket_epoch + 1, bucket_seconds):
            window_used += int(buckets_clean.get(str(be), 0))

        # Daily usage
        daily_used = int(daily.get(day_key, 0))

        # Determine if this request would violate limits
        violates_daily = (daily_limit > 0) and (daily_used + 1 > daily_limit)
        violates_window = (window_used + 1 > window_limit)

        # If violates, record violation counters and maybe auto-disable
        if violates_daily or violates_window:
            vtype = "daily" if violates_daily else "window"
            meta.violation_type = vtype

            # Retry-After:
            if vtype == "window":
                meta.retry_after = max(0, window_reset - now_epoch)
            else:
                meta.retry_after = max(0, daily_reset - now_epoch)

            # Remaining stays at 0 for violating dimension
            meta.window_remaining = max(0, window_limit - window_used)
            if daily_limit > 0:
                meta.daily_remaining = max(0, daily_limit - daily_used)

            # 1h abuse doc (TTL)
            transaction.set(
                abuse_1h_ref,
                {
                    "key_id": key_id,
                    "expires_at_utc": now + timedelta(seconds=ABUSE_1H_TTL_SECONDS),
                },
                merge=True,
            )
            transaction.update(abuse_1h_ref, _abuse_doc_update(vtype))

            # 24h abuse doc (TTL)
            transaction.set(
                abuse_24h_ref,
                {
                    "key_id": key_id,
                    "expires_at_utc": now + timedelta(seconds=ABUSE_24H_TTL_SECONDS),
                },
                merge=True,
            )
            transaction.update(abuse_24h_ref, _abuse_doc_update(vtype))

            # Read current abuse counts to decide auto-disable
            a1 = abuse_1h_ref.get(transaction=transaction).to_dict() or {}
            a24 = abuse_24h_ref.get(transaction=transaction).to_dict() or {}

            c1 = _read_count_field(a1, "count_total")
            c24 = _read_count_field(a24, "count_total")

            # Auto-disable if exceeded thresholds
            if (AUTO_DISABLE_1H_THRESHOLD > 0 and c1 >= AUTO_DISABLE_1H_THRESHOLD) or (
                AUTO_DISABLE_24H_THRESHOLD > 0 and c24 >= AUTO_DISABLE_24H_THRESHOLD
            ):
                meta.auto_disabled = True
                transaction.update(
                    key_ref,
                    {
                        "active": False,
                        "auto_disabled_at_utc": now,
                        "auto_disabled_reason": f"rate_limit_violations:{c1}in1h,{c24}in24h",
                        "updated_at_utc": now,
                    },
                )

            return False, meta

        # Otherwise: allow request, increment counters atomically
        # Update bucket count
        bkey = str(bucket_epoch)
        buckets_clean[bkey] = int(buckets_clean.get(bkey, 0)) + 1

        # Update daily
        daily_new = dict(daily)
        daily_new[day_key] = int(daily_new.get(day_key, 0)) + 1

        # Persist
        transaction.set(
            rl_ref,
            {
                "key_id": key_id,
                "buckets": buckets_clean,
                "daily": daily_new,
                "bucket_expires_at_utc": now + timedelta(seconds=RL_BUCKET_TTL_SECONDS),
                "daily_expires_at_utc": now + timedelta(seconds=RL_DAILY_TTL_SECONDS),
                "updated_at_utc": now,
            },
            merge=True,
        )

        # Compute remaining
        window_used2 = window_used + 1
        meta.window_remaining = max(0, window_limit - window_used2)
        if daily_limit > 0:
            daily_used2 = daily_used + 1
            meta.daily_remaining = max(0, daily_limit - daily_used2)

        return True, meta

    tx = db.transaction()
    allowed, meta = _tx(tx)

    # store for middleware/header attachment
    request.state.rate_limit_meta = meta
    request.state.rate_limit_headers = build_rate_limit_headers(meta)

    return allowed, meta


# FastAPI-friendly helper: raise 429 if not allowed
def enforce_rate_limit_or_429(
    db: firestore.Client,
    request: Request,
    key_id: str,
    key_doc: Dict[str, Any],
) -> None:
    allowed, meta = enforce_rate_limit(db, request, key_id, key_doc)
    if allowed:
        return

    raise HTTPException(
        status_code=429,
        detail={"error": "rate_limited", "violation": meta.violation_type or "unknown"},
        headers=build_rate_limit_headers(meta),
    )