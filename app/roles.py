from __future__ import annotations

from typing import Optional


LEGACY_ACADEMIC_LEAD_ROLES = {"academic_lead", "instructor"}
VALID_ROLES = {
    "student",
    "teacher",
    "institution_admin",
    "academic_lead",
    "instructor",
    "admin",
}
GLOBAL_ACADEMIC_ROLES = {"academic_lead", "instructor", "admin"}
INSTITUTION_OPERATOR_ROLES = {"teacher", "institution_admin", "admin"}
REVIEW_BYPASS_ROLES = {
    "teacher",
    "institution_admin",
    "academic_lead",
    "instructor",
    "admin",
}


def normalize_role(value: Optional[str], default: str = "student") -> str:
    normalized = str(value or "").strip().lower()
    if normalized in VALID_ROLES:
        return normalized
    return default


def is_valid_role(value: Optional[str]) -> bool:
    return normalize_role(value, default="") in VALID_ROLES


def is_admin_role(value: Optional[str]) -> bool:
    return normalize_role(value, default="") == "admin"


def is_academic_lead_role(value: Optional[str]) -> bool:
    return normalize_role(value, default="") in LEGACY_ACADEMIC_LEAD_ROLES or is_admin_role(value)


def is_teacher_role(value: Optional[str]) -> bool:
    return normalize_role(value, default="") == "teacher"


def is_institution_admin_role(value: Optional[str]) -> bool:
    return normalize_role(value, default="") == "institution_admin"


def is_institution_operator_role(value: Optional[str]) -> bool:
    return normalize_role(value, default="") in INSTITUTION_OPERATOR_ROLES


def is_review_bypass_role(value: Optional[str]) -> bool:
    return normalize_role(value, default="") in REVIEW_BYPASS_ROLES
