from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from fastapi import Depends, HTTPException, Request, status
from google.cloud import firestore

# --- Firestore client ---
_db = firestore.Client()

# --- Defaults (Cloud Run env vars) ---
DEFAULT_BUCKET_SECONDS = int(os.getenv("RL_BUCKET_SECONDS", "10"))
DEFAULT_WINDOW_SECONDS = int(os.getenv("RL_WINDOW_SECONDS", "60"))
DEFAULT_WINDOW_LIMIT = int(os.getenv("RL_WINDOW_LIMIT", "60"))

# daily quota: 0 or unset => disabled by default
DEFAULT_DAILY_LIMIT = int(os.getenv("RL_DAILY_LIMIT", "0"))

RL_COLLECTION = os.getenv("RL_COLLECTION", "api_key_rl")


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int
    window_remaining: int
    window_limit: int
    daily_remaining: Optional[int]
    daily_limit: Optional[int]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _yyyymmdd(dt: datetime) -> str:
    return dt.strftime("%Y%m%d")


def _bucket_id(epoch_seconds: int, bucket_seconds: int) -> int:
    return epoch_seconds // bucket_seconds


def _active_bucket_ids(now_epoch: int, bucket_seconds: int, window_seconds: int) -> Tuple[int, ...]:
    # e.g. window=60, bucket=10 -> 6 buckets: current and previous 5
    n = max(1, window_seconds // bucket_seconds)
    current = _bucket_id(now_epoch, bucket_seconds)
    return tuple(current - i for i in range(n))


def _trim_buckets(buckets: Dict[str, int], keep_ids: Tuple[int, ...]) -> Dict[str, int]:
    keep = set(str(bid) for bid in keep_ids)
    return {k: int(v) for k, v in buckets.items() if k in keep}


def _sum_buckets(buckets: Dict[str, int], ids: Tuple[int, ...]) -> int:
    total = 0
    for bid in ids:
        total += int(buckets.get(str(bid), 0))
    return total


def _calc_retry_after(now_epoch: int, bucket_seconds: int) -> int:
    # retry after the next bucket boundary
    # e.g. bucket=10, if we are 123456789 -> remainder 9 => retry after 1 sec
    rem = now_epoch % bucket_seconds
    return max(1, bucket_seconds - rem)


def get_rate_limit_policy_for_key(key_id: str) -> dict:
    """
    Option A (now): global defaults.
    Option B (later): read your API key doc (or scope policy) and return overrides.
    """
    daily_limit = DEFAULT_DAILY_LIMIT if DEFAULT_DAILY_LIMIT > 0 else None
    return {
        "bucket_seconds": DEFAULT_BUCKET_SECONDS,
        "window_seconds": DEFAULT_WINDOW_SECONDS,
        "window_limit": DEFAULT_WINDOW_LIMIT,
        "daily_limit": daily_limit,
    }


def rate_limit_api_key_dependency(request: Request) -> None:
    """
    Enforces RL only for X-API-Key auth mode.
    Assumes your earlier dependency already set request.state.api_key_id.
    """
    key_id = getattr(request.state, "api_key_id", None)
    if not key_id:
        # Not an API-key request; do nothing.
        return

    policy = get_rate_limit_policy_for_key(key_id)
    bucket_seconds = int(policy["bucket_seconds"])
    window_seconds = int(policy["window_seconds"])
    window_limit = int(policy["window_limit"])
    daily_limit = policy.get("daily_limit")  # int or None

    now = _utc_now()
    now_epoch = int(now.timestamp())
    today = _yyyymmdd(now)

    bucket_ids = _active_bucket_ids(now_epoch, bucket_seconds, window_seconds)
    current_bucket = str(bucket_ids[0])

    doc_ref = _db.collection(RL_COLLECTION).document(key_id)
    txn = _db.transaction()

    @firestore.transactional
    def _tx(transaction: firestore.Transaction) -> RateLimitDecision:
        snap = doc_ref.get(transaction=transaction)
        data = snap.to_dict() if snap.exists else {}

        buckets: Dict[str, int] = dict(data.get("buckets", {}) or {})
        buckets = _trim_buckets(buckets, bucket_ids)

        used_in_window = _sum_buckets(buckets, bucket_ids)

        # Daily quota bookkeeping (optional)
        daily_enabled = bool(daily_limit and daily_limit > 0)
        stored_day = data.get("daily_yyyymmdd")
        daily_count = int(data.get("daily_count", 0))

        if daily_enabled:
            if stored_day != today:
                stored_day = today
                daily_count = 0

        # Check window limit
        if used_in_window >= window_limit:
            retry_after = _calc_retry_after(now_epoch, bucket_seconds)
            return RateLimitDecision(
                allowed=False,
                retry_after_seconds=retry_after,
                window_remaining=0,
                window_limit=window_limit,
                daily_remaining=(max(0, daily_limit - daily_count) if daily_enabled else None),
                daily_limit=(daily_limit if daily_enabled else None),
            )

        # Check daily limit (if enabled)
        if daily_enabled and daily_count >= int(daily_limit):
            # daily retry_after: seconds until next UTC day
            tomorrow = datetime(now.year, now.month, now.day, tzinfo=timezone.utc).timestamp() + 86400
            retry_after = max(60, int(tomorrow - now_epoch))
            return RateLimitDecision(
                allowed=False,
                retry_after_seconds=retry_after,
                window_remaining=max(0, window_limit - used_in_window),
                window_limit=window_limit,
                daily_remaining=0,
                daily_limit=int(daily_limit),
            )

        # Apply increment to current bucket and daily count
        buckets[current_bucket] = int(buckets.get(current_bucket, 0)) + 1
        used_in_window_after = used_in_window + 1

        update_doc = {
            "key_id": key_id,
            "bucket_seconds": bucket_seconds,
            "window_seconds": window_seconds,
            "window_limit": window_limit,
            "buckets": buckets,
            "updated_at": firestore.SERVER_TIMESTAMP,
        }

        if daily_enabled:
            daily_count_after = daily_count + 1
            update_doc.update({
                "daily_enabled": True,
                "daily_yyyymmdd": stored_day,
                "daily_limit": int(daily_limit),
                "daily_count": daily_count_after,
            })

        transaction.set(doc_ref, update_doc, merge=True)

        return RateLimitDecision(
            allowed=True,
            retry_after_seconds=0,
            window_remaining=max(0, window_limit - used_in_window_after),
            window_limit=window_limit,
            daily_remaining=(max(0, int(daily_limit) - (daily_count + 1)) if daily_enabled else None),
            daily_limit=(int(daily_limit) if daily_enabled else None),
        )

    decision = _tx(txn)

    # Add standard-ish headers for observability
    # (FastAPI lets us set response headers via exception detail or middleware;
    #  easiest is to throw HTTPException with headers on deny)
    if not decision.allowed:
        headers = {
            "Retry-After": str(decision.retry_after_seconds),
            "X-RateLimit-Limit": str(decision.window_limit),
            "X-RateLimit-Remaining": str(decision.window_remaining),
        }
        if decision.daily_limit is not None and decision.daily_remaining is not None:
            headers["X-RateLimit-Daily-Limit"] = str(decision.daily_limit)
            headers["X-RateLimit-Daily-Remaining"] = str(decision.daily_remaining)

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers=headers,
        )


def RateLimitDepends():
    return Depends(rate_limit_api_key_dependency)