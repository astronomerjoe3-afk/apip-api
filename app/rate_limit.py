from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, Tuple

from fastapi import Depends, HTTPException, Request
from google.cloud import firestore


# -------------------------
# Helpers
# -------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _epoch_seconds(dt: datetime) -> int:
    return int(dt.timestamp())

def _floor_to_bucket(epoch_s: int, bucket_seconds: int) -> int:
    return (epoch_s // bucket_seconds) * bucket_seconds

def _today_utc_str(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d")


# -------------------------
# Rate-limit primitives
# -------------------------

@dataclass(frozen=True)
class RateLimitPolicy:
    window_limit: int
    window_seconds: int
    bucket_seconds: int
    daily_limit: int

    @staticmethod
    def from_key_doc(d: Dict[str, Any]) -> "RateLimitPolicy":
        # sane defaults
        wl = int(d.get("rl_window_limit") or 10)
        ws = int(d.get("rl_window_seconds") or 60)
        bs = int(d.get("rl_bucket_seconds") or 10)
        dl = int(d.get("rl_daily_limit") or 1000)

        # harden
        if ws <= 0:
            ws = 60
        if bs <= 0:
            bs = 10
        # avoid silly configs
        bs = min(bs, ws)
        wl = max(1, wl)
        dl = max(1, dl)

        return RateLimitPolicy(
            window_limit=wl,
            window_seconds=ws,
            bucket_seconds=bs,
            daily_limit=dl,
        )


@dataclass(frozen=True)
class RateLimitMeta:
    allowed: bool
    violation_type: Optional[str]  # "window" | "daily" | None
    # window counters
    window_limit: int
    window_used: int
    window_remaining: int
    window_reset_epoch: int
    # daily counters
    daily_limit: int
    daily_used: int
    daily_remaining: int
    daily_reset_epoch: int
    # retry
    retry_after: int
    # debug
    bucket_start_epoch: int
    now_epoch: int


def build_rate_limit_headers(meta: RateLimitMeta) -> Dict[str, str]:
    # Note: Retry-After is only meaningful on 429 responses, but we return it always for convenience.
    return {
        "X-RateLimit-Limit": str(meta.window_limit),
        "X-RateLimit-Remaining": str(max(0, meta.window_remaining)),
        "X-RateLimit-Reset": str(meta.window_reset_epoch),
        "X-RateLimit-Daily-Limit": str(meta.daily_limit),
        "X-RateLimit-Daily-Remaining": str(max(0, meta.daily_remaining)),
        "X-RateLimit-Daily-Reset": str(meta.daily_reset_epoch),
        "Retry-After": str(max(0, meta.retry_after)),
    }


# -------------------------
# Storage layout (Firestore)
# -------------------------
#
# rl_counters/{key_id}/buckets/{bucket_start_epoch}
#   - count: int
#   - bucket_start_epoch: int
#   - ts: datetime
#   - expires_at_utc: datetime   (TTL)
#
# rl_counters/{key_id}/days/{YYYY-MM-DD}
#   - count: int
#   - day: "YYYY-MM-DD"
#   - day_start_epoch: int
#   - ts: datetime
#   - expires_at_utc: datetime   (TTL)
#
# This design:
# - avoids scanning audit_logs for enforcement
# - is transaction-safe under concurrency
# - supports TTL cleanup
#


def _bucket_docref(db: firestore.Client, key_id: str, bucket_start_epoch: int) -> firestore.DocumentReference:
    return (
        db.collection("rl_counters")
          .document(key_id)
          .collection("buckets")
          .document(str(bucket_start_epoch))
    )

def _day_docref(db: firestore.Client, key_id: str, day_str: str) -> firestore.DocumentReference:
    return (
        db.collection("rl_counters")
          .document(key_id)
          .collection("days")
          .document(day_str)
    )


def _bucket_expires_at(now_dt: datetime, policy: RateLimitPolicy) -> datetime:
    # Keep bucket docs long enough to cover any window lookback + minor skew.
    return now_dt + timedelta(seconds=policy.window_seconds * 2)

def _day_expires_at(now_dt: datetime) -> datetime:
    # Keep daily docs slightly longer than 24h to cover time skew.
    return now_dt + timedelta(days=2)


# -------------------------
# Core enforcement
# -------------------------

def enforce_rate_limit(
    *,
    db: firestore.Client,
    key_id: str,
    policy_dict: Dict[str, Any],
) -> RateLimitMeta:
    """
    Transaction-safe rate limit enforcement using:
    - rolling window sum over last N buckets (N = window_seconds / bucket_seconds)
    - daily counter doc
    """
    policy = RateLimitPolicy.from_key_doc(policy_dict)

    now_dt = _now()
    now_epoch = _epoch_seconds(now_dt)

    bucket_start = _floor_to_bucket(now_epoch, policy.bucket_seconds)
    bucket_count = int(math.ceil(policy.window_seconds / policy.bucket_seconds))
    # We sum over these bucket start epochs:
    # [bucket_start - (N-1)*bucket_seconds, ..., bucket_start]
    bucket_epochs = [bucket_start - i * policy.bucket_seconds for i in range(bucket_count)]
    bucket_epochs.reverse()

    day_str = _today_utc_str(now_dt)

    # reset epochs (for headers)
    window_reset_epoch = bucket_start + policy.bucket_seconds  # next bucket boundary
    # daily reset at next midnight UTC
    tomorrow = (now_dt.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1))
    daily_reset_epoch = _epoch_seconds(tomorrow)

    # retry-after default: seconds until next bucket boundary
    retry_after = max(0, window_reset_epoch - now_epoch)

    @firestore.transactional
    def _tx(transaction: firestore.Transaction) -> RateLimitMeta:
        # Read all relevant buckets + daily in one transaction.
        bucket_refs = [_bucket_docref(db, key_id, e) for e in bucket_epochs]
        day_ref = _day_docref(db, key_id, day_str)

        bucket_snaps = [transaction.get(r) for r in bucket_refs]
        day_snap = transaction.get(day_ref)

        # Sum rolling window usage
        window_used = 0
        for snap in bucket_snaps:
            if snap.exists:
                d = snap.to_dict() or {}
                window_used += int(d.get("count") or 0)

        daily_used = 0
        if day_snap.exists:
            dday = day_snap.to_dict() or {}
            daily_used = int(dday.get("count") or 0)

        # Decide allow/deny WITHOUT consuming quota on deny.
        violation_type: Optional[str] = None
        if daily_used >= policy.daily_limit:
            violation_type = "daily"
        elif window_used >= policy.window_limit:
            violation_type = "window"

        allowed = violation_type is None

        # If allowed, increment current bucket + daily.
        if allowed:
            # increment bucket doc
            cur_ref = _bucket_docref(db, key_id, bucket_start)
            cur_snap = next((s for s in bucket_snaps if s.reference.id == str(bucket_start)), None)

            if cur_snap and cur_snap.exists:
                transaction.update(cur_ref, {
                    "count": firestore.Increment(1),
                    "ts": now_dt,
                    "expires_at_utc": _bucket_expires_at(now_dt, policy),
                })
            else:
                transaction.set(cur_ref, {
                    "count": 1,
                    "bucket_start_epoch": bucket_start,
                    "ts": now_dt,
                    "expires_at_utc": _bucket_expires_at(now_dt, policy),
                }, merge=True)

            # increment daily doc
            if day_snap.exists:
                transaction.update(day_ref, {
                    "count": firestore.Increment(1),
                    "ts": now_dt,
                    "expires_at_utc": _day_expires_at(now_dt),
                })
            else:
                day_start = now_dt.replace(hour=0, minute=0, second=0, microsecond=0)
                transaction.set(day_ref, {
                    "count": 1,
                    "day": day_str,
                    "day_start_epoch": _epoch_seconds(day_start),
                    "ts": now_dt,
                    "expires_at_utc": _day_expires_at(now_dt),
                }, merge=True)

            # Update the “used” values in the response as if the increment already happened.
            window_used_after = window_used + 1
            daily_used_after = daily_used + 1
        else:
            window_used_after = window_used
            daily_used_after = daily_used

        meta = RateLimitMeta(
            allowed=allowed,
            violation_type=violation_type,
            window_limit=policy.window_limit,
            window_used=window_used_after,
            window_remaining=policy.window_limit - window_used_after,
            window_reset_epoch=window_reset_epoch,
            daily_limit=policy.daily_limit,
            daily_used=daily_used_after,
            daily_remaining=policy.daily_limit - daily_used_after,
            daily_reset_epoch=daily_reset_epoch,
            retry_after=retry_after,
            bucket_start_epoch=bucket_start,
            now_epoch=now_epoch,
        )
        return meta

    tx = db.transaction()
    return _tx(tx)


# -------------------------
# FastAPI dependency
# -------------------------

class RateLimitDepends:
    """
    Reads request.state.key_policy and request.state.key_id, enforces RL,
    and stores headers in request.state.rate_limit_headers for a response middleware to attach.
    """
    def __init__(self) -> None:
        pass

    def __call__(self, request: Request) -> Any:
        db: Optional[firestore.Client] = getattr(request.app.state, "db", None)  # set in main.py
        if db is None:
            raise HTTPException(status_code=503, detail="Firestore not available")

        key_id: Optional[str] = getattr(request.state, "api_key_id", None) or getattr(request.state, "key_id", None)
        policy: Optional[Dict[str, Any]] = getattr(request.state, "key_policy", None)

        if not key_id or not isinstance(policy, dict):
            # programmer error: dependency order is wrong
            raise HTTPException(status_code=500, detail="RateLimitDepends requires api_key auth first")

        meta = enforce_rate_limit(db=db, key_id=key_id, policy_dict=policy)
        headers = build_rate_limit_headers(meta)
        request.state.rate_limit_headers = headers  # middleware in main.py will attach these

        if not meta.allowed:
            # The caller will return 429
            raise HTTPException(status_code=429, detail={"error": "rate_limited", "type": meta.violation_type})

        return {"ok": True}