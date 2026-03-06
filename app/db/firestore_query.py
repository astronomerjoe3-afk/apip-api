"""
Firestore query helpers for APIP.

Purpose
-------
Firestore's Python client now prefers the FieldFilter API instead of
positional arguments in `.where(field, op, value)`.

This module centralizes that pattern so the rest of the codebase
remains clean and future-proof.

Usage
-----
from app.db.firestore_query import where_eq

query = where_eq(db.collection("lessons"), "module_id", module_id)

"""

from __future__ import annotations

from google.cloud import firestore


def where_eq(query, field: str, value):
    """
    Apply equality filter using the modern FieldFilter API.
    """
    return query.where(filter=firestore.FieldFilter(field, "==", value))


def where_lt(query, field: str, value):
    """
    Less-than filter.
    """
    return query.where(filter=firestore.FieldFilter(field, "<", value))


def where_lte(query, field: str, value):
    """
    Less-than-or-equal filter.
    """
    return query.where(filter=firestore.FieldFilter(field, "<=", value))


def where_gt(query, field: str, value):
    """
    Greater-than filter.
    """
    return query.where(filter=firestore.FieldFilter(field, ">", value))


def where_gte(query, field: str, value):
    """
    Greater-than-or-equal filter.
    """
    return query.where(filter=firestore.FieldFilter(field, ">=", value))