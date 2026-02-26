from __future__ import annotations

import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, Tuple, List

from google.cloud import firestore
from google.api_core import exceptions as g_exceptions


# =========================
# Time helpers
# =========================

def now_utc_dt() -> datetime:
    return datetime.now(timezone.utc)

def epoch_seconds(dt: datetime) -> int:
    return int(dt.timestamp())

def ttl_dt(days: int) -> datetime:
    return now_utc_dt() + timedelta(days=days)

def ttl_seconds(seconds: int) -> datetime:
    return now_utc_dt() + timedelta(seconds=seconds)

def clamp_int(v: Any, default: int, lo: int, hi: int) -> int:
    try:
        x = int(v)
    except Exception:
        return default
    return max(lo, min(hi, x))


# =========================
# Policy defaults (safe)
# =========================

DEFAULT_WINDOW_LIMIT = int(os.getenv("RL_DEFAULT_WINDOW_LIMIT", "60"))
DEFAULT_WINDOW_SECONDS = int(os.getenv("RL_DEFAULT_WINDOW_SECONDS", "60"))
DEFAULT_BUCKET_SECONDS = int(os.getenv("RL_DEFAULT_BUCKET_SECONDS", "10"))
DEFAULT_DAILY_LIMIT = int(os.getenv("RL_DEFAULT_DAILY_LIMIT", "1000"))

# Auto-disable thresholds (violations)
AUTO_DISABLE_WINDOW_VIOLATIONS_1H = int(os.getenv("RL_AUTO_DISABLE_WINDOW_1H", "20"))
AUTO_DISABLE_DAILY_VIOLATIONS_24H = int(os.getenv("RL_AUTO_DISABLE_DAILY_24H", "50"))

# TTLs for counter docs (in seconds)
TTL_ABUSE_1H_SECONDS = 60 * 60 + 60       # 1h + cushion
TTL_ABUSE_24H_SECONDS = 24 * 60 * 60 + 60 # 24h + cushion

# Firestore collections used by rate limiting
COL_RL_STATE = "rl_state"                # per key: window/daily/bucket counters
COL_ABUSE_1H = "api_key_abuse_1h"        # per key: 1h violation counts (TTL)
COL_ABUSE_24H = "api_key_abuse_24h"      # per key: 24h violation counts (TTL)
COL_GABUSE_1H = "global_abuse_1h"        # global: 1h violation counts (TTL)
COL_GABUSE_24H = "global_abuse_24h"      # global: 24h violation counts (TTL)

# The keys collection name in your API
COL_KEYS = "api_keys"


@dataclass
class RLDecision:
    allowed: bool
    violation: str  # "", "window", "daily"
    headers: Dict[str, str]
    auto_disabled: bool


def _effective_policy(key_doc: Dict[str, Any]) -> Dict[str, int]:
    """
    Supports per-key policy fields:
      rl_window_limit, rl_window_seconds, rl_bucket_seconds, rl_daily_limit
    Falls back to env defaults.
    """
    window_limit = clamp_int(key_doc.get("rl_window_limit"), DEFAULT_WINDOW_LIMIT, 1, 1_000_000)
    window_seconds = clamp_int(key_doc.get("rl_window_seconds"), DEFAULT_WINDOW_SECONDS, 1, 7 * 24 * 3600)
    bucket_seconds = clamp_int(key_doc.get("rl_bucket_seconds"), DEFAULT_BUCKET_SECONDS, 1, window_seconds)
    daily_limit = clamp_int(key_doc.get("rl_daily_limit"), DEFAULT_DAILY_LIMIT, 1, 10_000_000)

    # ensure bucket <= window
    bucket_seconds = min(bucket_seconds, window_seconds)

    return {
        "rl_window_limit": window_limit,
        "rl_window_seconds": window_seconds,
        "rl_bucket_seconds": bucket_seconds,
        "rl_daily_limit": daily_limit,
    }


def _build_headers(policy: Dict[str, int], state: Dict[str, Any], violation: str) -> Dict[str, str]:
    """
    Standard + your custom headers.
    """
    # Window
    w_limit = int(policy["rl_window_limit"])
    w_remaining = int(state.get("window_remaining", 0))
    w_reset = int(state.get("window_reset", 0))

    # Daily
    d_limit = int(policy["rl_daily_limit"])
    d_remaining = int(state.get("daily_remaining", 0))
    d_reset = int(state.get("daily_reset", 0))

    retry_after = int(state.get("retry_after", 0))

    h: Dict[str, str] = {
        "X-RateLimit-Limit": str(w_limit),
        "X-RateLimit-Remaining": str(max(0, w_remaining)),
        "X-RateLimit-Reset": str(w_reset),
        "X-RateLimit-Daily-Limit": str(d_limit),
        "X-RateLimit-Daily-Remaining": str(max(0, d_remaining)),
        "X-RateLimit-Daily-Reset": str(d_reset),
    }

    if violation:
        h["X-RateLimit-Violation"] = violation
        h["Retry-After"] = str(max(0, retry_after))

    return h


def _floor_to_bucket(t: int, bucket_seconds: int) -> int:
    return t - (t % bucket_seconds)


def _compute_daily_reset_epoch(t: int) -> int:
    # daily reset at 00:00 UTC next day
    dt = datetime.fromtimestamp(t, tz=timezone.utc)
    tomorrow = (dt + timedelta(days=1)).date()
    reset_dt = datetime(tomorrow.year, tomorrow.month, tomorrow.day, tzinfo=timezone.utc)
    return epoch_seconds(reset_dt)


def _safe_tx_get(txn: firestore.Transaction, ref: firestore.DocumentReference) -> Optional[firestore.DocumentSnapshot]:
    snap = txn.get(ref)
    if isinstance(snap, list):
        return snap[0] if snap else None
    return snap


def _inc_violation_counters_in_txn(
    txn: firestore.Transaction,
    db: firestore.Client,
    key_id: str,
    violation: str,
) -> None:
    """
    Write per-key + global violation counters using TTL docs.
    IMPORTANT: read-before-write ordering.
    """
    if violation not in ("window", "daily"):
        return

    now = now_utc_dt()
    # per-key docs
    ref_1h = db.collection(COL_ABUSE_1H).document(key_id)
    ref_24h = db.collection(COL_ABUSE_24H).document(key_id)
    # global docs
    g1h = db.collection(COL_GABUSE_1H).document("global")
    g24h = db.collection(COL_GABUSE_24H).document("global")

    # READS FIRST
    s1 = _safe_tx_get(txn, ref_1h)
    s2 = _safe_tx_get(txn, ref_24h)
    s3 = _safe_tx_get(txn, g1h)
    s4 = _safe_tx_get(txn, g24h)

    # WRITES AFTER
    one_h_expires = ttl_seconds(TTL_ABUSE_1H_SECONDS)
    one_d_expires = ttl_seconds(TTL_ABUSE_24H_SECONDS)

    def bump(ref: firestore.DocumentReference, snap: Optional[firestore.DocumentSnapshot], expires: datetime) -> None:
        if snap is not None and snap.exists:
            txn.update(ref, {
                "total": firestore.Increment(1),
                violation: firestore.Increment(1),
                "updated_at_utc": now,
                "expires_at_utc": expires,  # refresh TTL
            })
        else:
            txn.set(ref, {
                "total": 1,
                "window": 1 if violation == "window" else 0,
                "daily": 1 if violation == "daily" else 0,
                "created_at_utc": now,
                "updated_at_utc": now,
                "expires_at_utc": expires,
            })

    bump(ref_1h, s1, one_h_expires)
    bump(ref_24h, s2, one_d_expires)
    bump(g1h, s3, one_h_expires)
    bump(g24h, s4, one_d_expires)


def _maybe_auto_disable_in_txn(
    txn: firestore.Transaction,
    db: firestore.Client,
    key_id: str,
    violation: str,
) -> bool:
    """
    Auto-disable if thresholds exceeded.
    Uses TTL docs to avoid scanning audit logs.

    Returns True if auto-disabled in this call.
    """
    if violation not in ("window", "daily"):
        return False

    # Determine which doc/threshold to check
    if violation == "window":
        ref = db.collection(COL_ABUSE_1H).document(key_id)
        threshold = AUTO_DISABLE_WINDOW_VIOLATIONS_1H
    else:
        ref = db.collection(COL_ABUSE_24H).document(key_id)
        threshold = AUTO_DISABLE_DAILY_VIOLATIONS_24H

    # READ FIRST
    snap = _safe_tx_get(txn, ref)
    data = (snap.to_dict() if snap and snap.exists else {}) or {}
    total = int(data.get("total", 0))

    if total < threshold:
        return False

    # Disable key (read-before-write)
    key_ref = db.collection(COL_KEYS).document(key_id)
    key_snap = _safe_tx_get(txn, key_ref)
    key_data = (key_snap.to_dict() if key_snap and key_snap.exists else {}) or {}

    # If already inactive, no-op
    if not key_data.get("active", False):
        return False

    now = now_utc_dt()
    txn.update(key_ref, {
        "active": False,
        "auto_disabled": True,
        "auto_disabled_at_utc": now,
        "auto_disabled_reason": f"threshold_exceeded:{violation}",
        "updated_at_utc": now,
    })
    return True


def enforce_rate_limit(db: firestore.Client, key_id: str, key_doc: Dict[str, Any]) -> RLDecision:
    """
    Transactional, Firestore-backed limiter:
    - per-key window counter
    - per-key daily counter
    - per-key bucket counter (optional shaping)
    - violation split: window vs daily
    - per-key + global violation TTL counters (no audit scan)
    - auto-disable thresholds
    """
    policy = _effective_policy(key_doc)

    window_limit = int(policy["rl_window_limit"])
    window_seconds = int(policy["rl_window_seconds"])
    bucket_seconds = int(policy["rl_bucket_seconds"])
    daily_limit = int(policy["rl_daily_limit"])

    key_ref = db.collection(COL_KEYS).document(key_id)
    state_ref = db.collection(COL_RL_STATE).document(key_id)

    t_now = int(time.time())
    window_reset = t_now + window_seconds
    daily_reset = _compute_daily_reset_epoch(t_now)
    bucket_reset = _floor_to_bucket(t_now, bucket_seconds) + bucket_seconds

    def _txn_logic(txn: firestore.Transaction) -> RLDecision:
        # ---- READS FIRST ----
        key_snap = _safe_tx_get(txn, key_ref)
        if not key_snap or not key_snap.exists:
            return RLDecision(False, "window", {"Retry-After": "1", "X-RateLimit-Violation": "window"}, False)

        kdoc = key_snap.to_dict() or {}
        if not kdoc.get("active", False):
            # Not an RL violation; this is "disabled"
            return RLDecision(False, "", {"X-API-Key-Disabled": "1"}, False)

        state_snap = _safe_tx_get(txn, state_ref)
        state = state_snap.to_dict() if state_snap and state_snap.exists else {}

        # Current counters & expiries
        w_count = int(state.get("window_count", 0))
        w_exp = int(state.get("window_reset", 0))

        d_count = int(state.get("daily_count", 0))
        d_exp = int(state.get("daily_reset", 0))

        b_count = int(state.get("bucket_count", 0))
        b_exp = int(state.get("bucket_reset", 0))

        # Reset if expired
        if w_exp <= t_now:
            w_count = 0
            w_exp = window_reset
        if d_exp <= t_now:
            d_count = 0
            d_exp = daily_reset
        if b_exp <= t_now:
            b_count = 0
            b_exp = bucket_reset

        # Evaluate violations: daily first (stronger), then window
        violation = ""
        retry_after = 0

        if d_count >= daily_limit:
            violation = "daily"
            retry_after = max(1, d_exp - t_now)
        elif w_count >= window_limit:
            violation = "window"
            retry_after = max(1, w_exp - t_now)

        # ---- WRITES AFTER ----
        if violation:
            # increment violation counters + maybe auto-disable
            _inc_violation_counters_in_txn(txn, db, key_id, violation)
            auto_disabled = _maybe_auto_disable_in_txn(txn, db, key_id, violation)

            headers_state = {
                "window_remaining": 0,
                "window_reset": w_exp,
                "daily_remaining": max(0, daily_limit - d_count),
                "daily_reset": d_exp,
                "retry_after": retry_after,
            }
            headers = _build_headers(policy, headers_state, violation)
            if auto_disabled:
                headers["X-API-Key-Auto-Disabled"] = "1"
            return RLDecision(False, violation, headers, auto_disabled)

        # Allowed → increment counters
        w_count += 1
        d_count += 1
        b_count += 1

        # For TTL support on state doc:
        # - Keep it alive slightly past the furthest reset to allow reporting
        furthest = max(w_exp, d_exp, b_exp)
        expires_at = datetime.fromtimestamp(furthest, tz=timezone.utc) + timedelta(minutes=10)

        if state_snap and state_snap.exists:
            txn.update(state_ref, {
                "window_count": w_count,
                "window_reset": w_exp,
                "daily_count": d_count,
                "daily_reset": d_exp,
                "bucket_count": b_count,
                "bucket_reset": b_exp,
                "updated_at_utc": now_utc_dt(),
                "expires_at_utc": expires_at,
            })
        else:
            txn.set(state_ref, {
                "window_count": w_count,
                "window_reset": w_exp,
                "daily_count": d_count,
                "daily_reset": d_exp,
                "bucket_count": b_count,
                "bucket_reset": b_exp,
                "created_at_utc": now_utc_dt(),
                "updated_at_utc": now_utc_dt(),
                "expires_at_utc": expires_at,
            })

        headers_state = {
            "window_remaining": max(0, window_limit - w_count),
            "window_reset": w_exp,
            "daily_remaining": max(0, daily_limit - d_count),
            "daily_reset": d_exp,
            "retry_after": 0,
        }
        headers = _build_headers(policy, headers_state, "")
        return RLDecision(True, "", headers, False)

    # Transaction wrapper
    try:
        txn = db.transaction()
        return txn.call(_txn_logic)
    except g_exceptions.FailedPrecondition:
        # Index/transaction precondition — return safe throttle to avoid 500
        return RLDecision(False, "window", {
            "X-RateLimit-Violation": "window",
            "Retry-After": "1",
        }, False)
    except Exception:
        # Never 500 due to limiter: fail-closed as 429 window
        return RLDecision(False, "window", {
            "X-RateLimit-Violation": "window",
            "Retry-After": "1",
        }, False)


def reset_key_counters(db: firestore.Client, key_id: str) -> Dict[str, Any]:
    """
    Admin helper: delete RL state + abuse counter docs for a key.
    Best-effort deletions.
    """
    paths = [
        (COL_RL_STATE, key_id),
        (COL_ABUSE_1H, key_id),
        (COL_ABUSE_24H, key_id),
    ]
    deleted: List[str] = []
    errors: List[str] = []

    for col, doc_id in paths:
        try:
            ref = db.collection(col).document(doc_id)
            ref.delete()
            deleted.append(f"{col}/{doc_id}")
        except Exception as e:
            errors.append(f"{col}/{doc_id}:{type(e).__name__}:{e}")

    return {"deleted": deleted, "errors": errors}