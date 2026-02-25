import os
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, Tuple

from fastapi import HTTPException, Request
from google.cloud import firestore

# =========================
# Collections
# =========================
COL_KEYS = "api_keys"                 # api_keys/{key_id}
COL_RL = "api_key_rl"                 # api_key_rl/{key_id} (buckets + daily)

# Per-key violation counters (TTL docs)
COL_ABUSE_1H = "api_key_abuse_1h"     # api_key_abuse_1h/{key_id}
COL_ABUSE_24H = "api_key_abuse_24h"   # api_key_abuse_24h/{key_id}

# Global violation counters (TTL docs)
COL_GLOBAL_ABUSE_1H = "global_abuse_1h"   # global_abuse_1h/global
COL_GLOBAL_ABUSE_24H = "global_abuse_24h" # global_abuse_24h/global

# Global posture (non-TTL)
COL_SECURITY = "security"             # security/posture


# =========================
# Defaults / env controls
# =========================
DEFAULT_WINDOW_LIMIT = int(os.getenv("RL_DEFAULT_WINDOW_LIMIT", "60"))
DEFAULT_WINDOW_SECONDS = int(os.getenv("RL_DEFAULT_WINDOW_SECONDS", "60"))
DEFAULT_BUCKET_SECONDS = int(os.getenv("RL_DEFAULT_BUCKET_SECONDS", "10"))
DEFAULT_DAILY_LIMIT = int(os.getenv("RL_DEFAULT_DAILY_LIMIT", "0"))  # 0 => disabled

AUTO_DISABLE_1H_THRESHOLD = int(os.getenv("RL_AUTO_DISABLE_1H_THRESHOLD", "30"))
AUTO_DISABLE_24H_THRESHOLD = int(os.getenv("RL_AUTO_DISABLE_24H_THRESHOLD", "200"))

ABUSE_1H_TTL_SECONDS = int(os.getenv("RL_ABUSE_1H_TTL_SECONDS", "3600"))
ABUSE_24H_TTL_SECONDS = int(os.getenv("RL_ABUSE_24H_TTL_SECONDS", str(24 * 3600)))

RL_BUCKET_TTL_SECONDS = int(os.getenv("RL_BUCKET_TTL_SECONDS", "7200"))  # ~2h
RL_DAILY_TTL_SECONDS = int(os.getenv("RL_DAILY_TTL_SECONDS", str(3 * 24 * 3600)))  # ~3d


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
    window_limit = _safe_int(key_doc.get("rl_window_limit"), DEFAULT_WINDOW_LIMIT)
    window_seconds = _safe_int(key_doc.get("rl_window_seconds"), DEFAULT_WINDOW_SECONDS)
    bucket_seconds = _safe_int(key_doc.get("rl_bucket_seconds"), DEFAULT_BUCKET_SECONDS)
    daily_limit = _safe_int(key_doc.get("rl_daily_limit"), DEFAULT_DAILY_LIMIT)

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
    headers: Dict[str, str] = {
        "X-RateLimit-Limit": str(meta.window_limit),
        "X-RateLimit-Remaining": str(max(0, meta.window_remaining)),
        "X-RateLimit-Reset": str(meta.window_reset),
        "Retry-After": str(max(0, meta.retry_after)),
    }

    if meta.daily_limit and meta.daily_limit > 0:
        headers["X-RateLimit-Daily-Limit"] = str(meta.daily_limit)
        headers["X-RateLimit-Daily-Remaining"] = str(max(0, int(meta.daily_remaining or 0)))
        headers["X-RateLimit-Daily-Reset"] = str(int(meta.daily_reset or 0))

    if meta.violation_type:
        headers["X-RateLimit-Violation"] = meta.violation_type
    if meta.auto_disabled:
        headers["X-API-Key-Auto-Disabled"] = "true"

    return headers


def _abuse_merge_fields(key_id: str, violation_type: str, ttl_seconds: int) -> Dict[str, Any]:
    # IMPORTANT: use only transaction.set(... merge=True) with increments (NO transaction.update)
    fields: Dict[str, Any] = {
        "key_id": key_id,
        "updated_at_utc": _now(),
        "expires_at_utc": _now() + timedelta(seconds=ttl_seconds),
        "count_total": firestore.Increment(1),
    }
    if violation_type == "window":
        fields["count_window"] = firestore.Increment(1)
    elif violation_type == "daily":
        fields["count_daily"] = firestore.Increment(1)
    else:
        fields["count_other"] = firestore.Increment(1)
    return fields


def _read_int(doc: Dict[str, Any], field: str) -> int:
    try:
        return int(doc.get(field) or 0)
    except Exception:
        return 0


def enforce_rate_limit(
    db: firestore.Client,
    request: Request,
    key_id: str,
    key_doc: Dict[str, Any],
) -> Tuple[bool, RLMeta]:
    policy = _policy_from_key_doc(key_doc)
    now = _now()

    window_limit = policy["window_limit"]
    window_seconds = policy["window_seconds"]
    bucket_seconds = policy["bucket_seconds"]
    daily_limit = policy["daily_limit"]

    now_epoch = _epoch(now)
    bucket_epoch = (now_epoch // bucket_seconds) * bucket_seconds

    window_start = (now_epoch // window_seconds) * window_seconds
    window_reset = window_start + window_seconds

    tomorrow = (now + timedelta(days=1)).date()
    daily_reset_dt = datetime(tomorrow.year, tomorrow.month, tomorrow.day, tzinfo=timezone.utc)
    daily_reset = _epoch(daily_reset_dt)
    day_key = _day_key(now)

    rl_ref = db.collection(COL_RL).document(key_id)
    key_ref = db.collection(COL_KEYS).document(key_id)

    abuse_1h_ref = db.collection(COL_ABUSE_1H).document(key_id)
    abuse_24h_ref = db.collection(COL_ABUSE_24H).document(key_id)

    g1_ref = db.collection(COL_GLOBAL_ABUSE_1H).document("global")
    g24_ref = db.collection(COL_GLOBAL_ABUSE_24H).document("global")

    posture_ref = db.collection(COL_SECURITY).document("posture")

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
        # Read current bucket state
        rl_snap = rl_ref.get(transaction=transaction)
        rl_data = rl_snap.to_dict() if rl_snap.exists else {}

        buckets: Dict[str, Any] = (rl_data.get("buckets") or {})
        daily: Dict[str, Any] = (rl_data.get("daily") or {})

        # Clean old buckets
        horizon = window_start - (2 * window_seconds)
        buckets_clean: Dict[str, int] = {}
        for k, v in buckets.items():
            try:
                k_int = int(k)
                if k_int >= horizon:
                    buckets_clean[str(k_int)] = int(v)
            except Exception:
                continue

        buckets_per_window = max(1, _ceil_div(window_seconds, bucket_seconds))
        earliest_bucket = bucket_epoch - (buckets_per_window - 1) * bucket_seconds

        window_used = 0
        for be in range(earliest_bucket, bucket_epoch + 1, bucket_seconds):
            window_used += int(buckets_clean.get(str(be), 0))

        daily_used = int(daily.get(day_key, 0))

        violates_daily = (daily_limit > 0) and (daily_used + 1 > daily_limit)
        violates_window = (window_used + 1 > window_limit)

        if violates_daily or violates_window:
            vtype = "daily" if violates_daily else "window"
            meta.violation_type = vtype

            meta.window_remaining = max(0, window_limit - window_used)
            if daily_limit > 0:
                meta.daily_remaining = max(0, daily_limit - daily_used)

            meta.retry_after = max(
                0,
                (daily_reset - now_epoch) if vtype == "daily" else (window_reset - now_epoch),
            )

            # ✅ Violation counters (per-key + global) via merge SET with increments (no update)
            transaction.set(
                abuse_1h_ref,
                _abuse_merge_fields(key_id, vtype, ABUSE_1H_TTL_SECONDS),
                merge=True,
            )
            transaction.set(
                abuse_24h_ref,
                _abuse_merge_fields(key_id, vtype, ABUSE_24H_TTL_SECONDS),
                merge=True,
            )
            transaction.set(
                g1_ref,
                _abuse_merge_fields("global", vtype, ABUSE_1H_TTL_SECONDS),
                merge=True,
            )
            transaction.set(
                g24_ref,
                _abuse_merge_fields("global", vtype, ABUSE_24H_TTL_SECONDS),
                merge=True,
            )

            # Read snapshots (safe: read is allowed) to evaluate auto-disable
            a1 = abuse_1h_ref.get(transaction=transaction).to_dict() or {}
            a24 = abuse_24h_ref.get(transaction=transaction).to_dict() or {}
            c1 = _read_int(a1, "count_total")
            c24 = _read_int(a24, "count_total")

            if (AUTO_DISABLE_1H_THRESHOLD > 0 and c1 >= AUTO_DISABLE_1H_THRESHOLD) or (
                AUTO_DISABLE_24H_THRESHOLD > 0 and c24 >= AUTO_DISABLE_24H_THRESHOLD
            ):
                meta.auto_disabled = True
                transaction.set(
                    key_ref,
                    {
                        "active": False,
                        "auto_disabled_at_utc": now,
                        "auto_disabled_reason": f"rate_limit_violations:{c1}in1h,{c24}in24h",
                        "updated_at_utc": now,
                    },
                    merge=True,
                )
                transaction.set(
                    posture_ref,
                    {
                        "updated_at_utc": now,
                        "auto_disabled_total": firestore.Increment(1),
                        "auto_disabled_last_at_utc": now,
                    },
                    merge=True,
                )

            return False, meta

        # Allow: increment bucket and daily
        bkey = str(bucket_epoch)
        buckets_clean[bkey] = int(buckets_clean.get(bkey, 0)) + 1

        daily_new = dict(daily)
        daily_new[day_key] = int(daily_new.get(day_key, 0)) + 1

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

        meta.window_remaining = max(0, window_limit - (window_used + 1))
        if daily_limit > 0:
            meta.daily_remaining = max(0, daily_limit - (daily_used + 1))

        return True, meta

    tx = db.transaction()
    allowed, meta = _tx(tx)

    request.state.rate_limit_meta = meta
    request.state.rate_limit_headers = build_rate_limit_headers(meta)
    return allowed, meta


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