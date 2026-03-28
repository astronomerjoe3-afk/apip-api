from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from fastapi import HTTPException

from app.common import normalize_module_id, parse_iso_utc, safe_list_str
from app.db.firestore import get_firestore_client
from app.roles import (
    is_academic_lead_role,
    is_admin_role,
    is_institution_operator_role,
    normalize_role,
)


INSTITUTIONS_COLLECTION = "institutions"
MEMBERSHIPS_COLLECTION = "institution_memberships"
CLASSES_COLLECTION = "institution_classes"
ASSIGNMENTS_COLLECTION = "institution_assignments"
SUBMISSIONS_COLLECTION = "institution_submissions"
DISCUSSIONS_COLLECTION = "institution_discussions"

INSTITUTION_MEMBERSHIP_ROLES = {"institution_admin", "teacher", "student"}
CLASS_MANAGER_ROLES = {"institution_admin", "teacher"}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _string(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _slugify(value: str) -> str:
    lowered = str(value or "").strip().lower()
    normalized = re.sub(r"[^a-z0-9]+", "-", lowered).strip("-")
    return normalized[:64] or "institution"


def _doc_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(6)}"


def _seat_band_for_size(student_count: int) -> Dict[str, Any]:
    if student_count <= 100:
        return {"code": "band_a", "label": "Band A", "range_label": "1-100 students"}
    if student_count <= 300:
        return {"code": "band_b", "label": "Band B", "range_label": "101-300 students"}
    if student_count <= 750:
        return {"code": "band_c", "label": "Band C", "range_label": "301-750 students"}
    if student_count <= 1500:
        return {"code": "band_d", "label": "Band D", "range_label": "751-1,500 students"}
    return {"code": "enterprise", "label": "Enterprise", "range_label": "1,500+ students"}


def _collection_items(collection_name: str) -> List[Dict[str, Any]]:
    db = get_firestore_client()
    items: List[Dict[str, Any]] = []
    for snap in db.collection(collection_name).stream():
        row = snap.to_dict() or {}
        row["id"] = snap.id
        items.append(row)
    return items


def _document_payload(collection_name: str, doc_id: str) -> Dict[str, Any]:
    db = get_firestore_client()
    snapshot = db.collection(collection_name).document(doc_id).get()
    if not snapshot.exists:
        return {}
    row = snapshot.to_dict() or {}
    row["id"] = snapshot.id
    return row


def _write_document(collection_name: str, doc_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    db = get_firestore_client()
    db.collection(collection_name).document(doc_id).set(payload, merge=True)
    stored = dict(payload)
    stored["id"] = doc_id
    return stored


def _membership_doc_id(institution_id: str, uid: str) -> str:
    return f"{institution_id}:{uid}"


def _is_active(value: Optional[str]) -> bool:
    return str(value or "active").strip().lower() not in {"inactive", "archived", "disabled"}


def _institution_sort_key(item: Dict[str, Any]) -> tuple[str, str]:
    return (str(item.get("name") or "").lower(), str(item.get("id") or ""))


def _class_sort_key(item: Dict[str, Any]) -> tuple[str, str]:
    return (str(item.get("term") or "").lower(), str(item.get("name") or "").lower())


def _assignment_sort_key(item: Dict[str, Any]) -> tuple[float, str]:
    due_score = parse_iso_utc(item.get("due_utc")) or float("inf")
    return (due_score, str(item.get("title") or "").lower())


def _member_record(records: Iterable[Dict[str, Any]], uid: Optional[str], institution_id: str) -> Optional[Dict[str, Any]]:
    normalized_uid = _string(uid)
    if not normalized_uid:
        return None
    for record in records:
        if _string(record.get("institution_id")) == institution_id and _string(record.get("uid")) == normalized_uid:
            return record
    return None


def _teacher_names_for_class(class_row: Dict[str, Any], memberships: List[Dict[str, Any]]) -> List[str]:
    teacher_uids = set(safe_list_str(class_row.get("teacher_uids"), max_items=20, max_len=128))
    names: List[str] = []
    for membership in memberships:
        if _string(membership.get("uid")) not in teacher_uids:
            continue
        names.append(
            _string(membership.get("display_name"))
            or _string(membership.get("email"))
            or _string(membership.get("uid"))
            or "Teacher"
        )
    return sorted(set(names))


def _can_view_all_classes(global_role: str, membership_role: Optional[str]) -> bool:
    return is_admin_role(global_role) or is_academic_lead_role(global_role) or membership_role == "institution_admin"


def _can_manage_members(global_role: str, membership_role: Optional[str], target_role: Optional[str] = None) -> bool:
    if is_admin_role(global_role):
        return True
    if membership_role == "institution_admin":
        return target_role in {None, "institution_admin", "teacher", "student"}
    if membership_role == "teacher":
        return target_role in {None, "student"}
    return False


def _can_manage_class(global_role: str, membership_role: Optional[str], class_row: Dict[str, Any], user_uid: str) -> bool:
    if is_admin_role(global_role) or membership_role == "institution_admin":
        return True
    if membership_role == "teacher":
        teacher_uids = set(safe_list_str(class_row.get("teacher_uids"), max_items=20, max_len=128))
        return user_uid in teacher_uids or _string(class_row.get("created_by_uid")) == user_uid
    return False


def _student_can_view_class(class_row: Dict[str, Any], user_uid: str) -> bool:
    student_uids = set(safe_list_str(class_row.get("student_uids"), max_items=4000, max_len=128))
    return user_uid in student_uids


def _normalize_membership_role(value: Any) -> str:
    role = str(value or "").strip().lower()
    if role in INSTITUTION_MEMBERSHIP_ROLES:
        return role
    return "student"


def _format_institution_row(
    institution: Dict[str, Any],
    memberships: List[Dict[str, Any]],
    classes: List[Dict[str, Any]],
    assignments: List[Dict[str, Any]],
    submissions: List[Dict[str, Any]],
) -> Dict[str, Any]:
    active_members = [row for row in memberships if _is_active(row.get("status"))]
    active_student_count = len([row for row in active_members if _normalize_membership_role(row.get("role")) == "student"])
    active_teacher_count = len([row for row in active_members if _normalize_membership_role(row.get("role")) == "teacher"])
    active_admin_count = len([row for row in active_members if _normalize_membership_role(row.get("role")) == "institution_admin"])
    committed_student_seats = max(1, int(institution.get("committed_student_seats") or 0))
    seat_band = _seat_band_for_size(committed_student_seats)
    scored_submissions = [row for row in submissions if row.get("score") is not None]
    average_score = None
    if scored_submissions:
        average_score = round(sum(float(row.get("score") or 0) for row in scored_submissions) / len(scored_submissions), 1)

    return {
        "id": institution.get("id"),
        "name": institution.get("name"),
        "slug": institution.get("slug"),
        "status": institution.get("status") or "active",
        "public_community_enabled": institution.get("public_community_enabled") is True,
        "committed_student_seats": committed_student_seats,
        "contract_start_utc": institution.get("contract_start_utc"),
        "contract_end_utc": institution.get("contract_end_utc"),
        "seat_band": seat_band,
        "active_student_count": active_student_count,
        "active_teacher_count": active_teacher_count,
        "active_institution_admin_count": active_admin_count,
        "seat_utilization_ratio": round(active_student_count / committed_student_seats, 4),
        "class_count": len(classes),
        "assignment_count": len(assignments),
        "submission_count": len(submissions),
        "pending_grading_count": len([row for row in submissions if str(row.get("status") or "").lower() == "submitted"]),
        "average_score": average_score,
    }


def _visible_public_topics(global_role: str, visible_institutions: List[Dict[str, Any]], memberships: List[Dict[str, Any]], user_uid: str) -> bool:
    if is_admin_role(global_role) or is_academic_lead_role(global_role) or is_institution_operator_role(global_role):
        return True

    student_memberships = [
        membership
        for membership in memberships
        if _string(membership.get("uid")) == user_uid
        and _normalize_membership_role(membership.get("role")) == "student"
        and _is_active(membership.get("status"))
    ]
    if not student_memberships:
        return True

    return any(item.get("public_community_enabled") is True for item in visible_institutions)


def build_institutions_workspace(user: Dict[str, Any]) -> Dict[str, Any]:
    user_uid = _string((user or {}).get("uid")) or ""
    global_role = normalize_role((user or {}).get("role"))
    institutions = sorted(_collection_items(INSTITUTIONS_COLLECTION), key=_institution_sort_key)
    memberships = _collection_items(MEMBERSHIPS_COLLECTION)
    classes = _collection_items(CLASSES_COLLECTION)
    assignments = _collection_items(ASSIGNMENTS_COLLECTION)
    submissions = _collection_items(SUBMISSIONS_COLLECTION)
    discussions = _collection_items(DISCUSSIONS_COLLECTION)

    visible_institutions: List[Dict[str, Any]] = []
    memberships_by_institution: Dict[str, Dict[str, Any]] = {}

    for institution in institutions:
        institution_id = str(institution.get("id") or "")
        membership = _member_record(memberships, user_uid, institution_id)
        if is_admin_role(global_role) or is_academic_lead_role(global_role) or membership:
            visible_institutions.append(institution)
            if membership:
                memberships_by_institution[institution_id] = membership

    public_topic_access = _visible_public_topics(global_role, visible_institutions, memberships, user_uid)
    institution_blocks: List[Dict[str, Any]] = []

    for institution in visible_institutions:
        institution_id = str(institution.get("id") or "")
        membership = memberships_by_institution.get(institution_id)
        membership_role = _normalize_membership_role((membership or {}).get("role"))
        institution_memberships = [
            row
            for row in memberships
            if _string(row.get("institution_id")) == institution_id and _is_active(row.get("status"))
        ]
        institution_classes = [
            row
            for row in classes
            if _string(row.get("institution_id")) == institution_id and _is_active(row.get("status"))
        ]
        institution_assignments = [
            row
            for row in assignments
            if _string(row.get("institution_id")) == institution_id and _is_active(row.get("status"))
        ]
        institution_submissions = [
            row
            for row in submissions
            if _string(row.get("institution_id")) == institution_id
        ]
        institution_discussions = [
            row
            for row in discussions
            if _string(row.get("institution_id")) == institution_id and str(row.get("scope") or "").lower() != "public_topic"
        ]

        class_name_by_id = {str(row.get("id") or ""): str(row.get("name") or "Class") for row in institution_classes}
        assignment_title_by_id = {str(row.get("id") or ""): str(row.get("title") or "Assignment") for row in institution_assignments}
        visible_classes: List[Dict[str, Any]] = []

        for class_row in sorted(institution_classes, key=_class_sort_key):
            class_id = str(class_row.get("id") or "")
            if _can_view_all_classes(global_role, membership_role):
                can_view = True
            elif membership_role == "teacher":
                can_view = _can_manage_class(global_role, membership_role, class_row, user_uid)
            elif membership_role == "student":
                can_view = _student_can_view_class(class_row, user_uid)
            else:
                can_view = False

            if not can_view:
                continue

            class_assignments = [row for row in institution_assignments if _string(row.get("class_id")) == class_id]
            class_submissions = [row for row in institution_submissions if _string(row.get("class_id")) == class_id]
            if membership_role == "student" and not _can_view_all_classes(global_role, membership_role):
                class_submissions = [row for row in class_submissions if _string(row.get("student_uid")) == user_uid]

            student_uids = safe_list_str(class_row.get("student_uids"), max_items=4000, max_len=128)
            visible_classes.append(
                {
                    "id": class_id,
                    "institution_id": institution_id,
                    "name": class_row.get("name"),
                    "term": class_row.get("term"),
                    "topic_focus": class_row.get("topic_focus"),
                    "status": class_row.get("status") or "active",
                    "join_code": class_row.get("join_code"),
                    "teacher_uids": safe_list_str(class_row.get("teacher_uids"), max_items=20, max_len=128),
                    "teacher_names": _teacher_names_for_class(class_row, institution_memberships),
                    "student_count": len(student_uids),
                    "student_uids": student_uids if _can_view_all_classes(global_role, membership_role) or membership_role in {"institution_admin", "teacher"} else [],
                    "assignment_count": len(class_assignments),
                    "pending_grading_count": len([row for row in class_submissions if str(row.get("status") or "").lower() == "submitted"]),
                    "assignments": sorted(
                        [
                            {
                                "id": row.get("id"),
                                "class_id": class_id,
                                "class_name": class_row.get("name"),
                                "title": row.get("title"),
                                "assignment_type": row.get("assignment_type"),
                                "instructions": row.get("instructions"),
                                "due_utc": row.get("due_utc"),
                                "grading_mode": row.get("grading_mode"),
                                "status": row.get("status"),
                                "resource_module_ids": safe_list_str(row.get("resource_module_ids"), max_items=20, max_len=24),
                                "resource_titles": safe_list_str(row.get("resource_titles"), max_items=20, max_len=120),
                                "external_resource_url": row.get("external_resource_url"),
                                "allow_resubmission": row.get("allow_resubmission") is not False,
                                "created_utc": row.get("created_utc"),
                                "created_by_uid": row.get("created_by_uid"),
                                "submission_total": len([item for item in class_submissions if _string(item.get("assignment_id")) == _string(row.get("id"))]),
                                "graded_total": len(
                                    [
                                        item
                                        for item in class_submissions
                                        if _string(item.get("assignment_id")) == _string(row.get("id")) and str(item.get("status") or "").lower() == "graded"
                                    ]
                                ),
                                "your_submission": next(
                                    (
                                        {
                                            "id": item.get("id"),
                                            "status": item.get("status"),
                                            "score": item.get("score"),
                                            "feedback": item.get("feedback"),
                                            "submitted_utc": item.get("submitted_utc"),
                                        }
                                        for item in class_submissions
                                        if _string(item.get("assignment_id")) == _string(row.get("id")) and _string(item.get("student_uid")) == user_uid
                                    ),
                                    None,
                                ),
                            }
                            for row in class_assignments
                        ],
                        key=_assignment_sort_key,
                    ),
                    "submissions": sorted(
                        [
                            {
                                "id": row.get("id"),
                                "assignment_id": row.get("assignment_id"),
                                "assignment_title": assignment_title_by_id.get(str(row.get("assignment_id") or ""), "Assignment"),
                                "student_uid": row.get("student_uid"),
                                "student_email": row.get("student_email"),
                                "status": row.get("status"),
                                "text_response": row.get("text_response"),
                                "link_url": row.get("link_url"),
                                "attachment_names": safe_list_str(row.get("attachment_names"), max_items=20, max_len=160),
                                "score": row.get("score"),
                                "feedback": row.get("feedback"),
                                "submitted_utc": row.get("submitted_utc"),
                                "feedback_utc": row.get("feedback_utc"),
                            }
                            for row in class_submissions
                        ],
                        key=lambda item: (parse_iso_utc(item.get("submitted_utc")) * -1, str(item.get("student_email") or "").lower()),
                    ),
                    "discussions": sorted(
                        [
                            {
                                "id": row.get("id"),
                                "scope": row.get("scope"),
                                "title": row.get("title"),
                                "body": row.get("body"),
                                "module_id": row.get("module_id"),
                                "created_by_uid": row.get("created_by_uid"),
                                "created_by_role": row.get("created_by_role"),
                                "created_utc": row.get("created_utc"),
                            }
                            for row in institution_discussions
                            if _string(row.get("class_id")) == class_id
                        ],
                        key=lambda item: parse_iso_utc(item.get("created_utc")) * -1,
                    ),
                }
            )

        flattened_assignments = [assignment for class_row in visible_classes for assignment in class_row.get("assignments", [])]
        flattened_submissions = [submission for class_row in visible_classes for submission in class_row.get("submissions", [])]
        visible_class_ids = {str(row.get("id") or "") for row in visible_classes}
        scoped_discussions = sorted(
            [
                {
                    "id": row.get("id"),
                    "scope": row.get("scope"),
                    "institution_id": institution_id,
                    "class_id": row.get("class_id"),
                    "class_name": class_name_by_id.get(str(row.get("class_id") or ""), "Class"),
                    "title": row.get("title"),
                    "body": row.get("body"),
                    "module_id": row.get("module_id"),
                    "created_by_uid": row.get("created_by_uid"),
                    "created_by_role": row.get("created_by_role"),
                    "created_utc": row.get("created_utc"),
                }
                for row in institution_discussions
                if _string(row.get("class_id")) in visible_class_ids or (_string(row.get("scope")) == "institution" and (membership is not None or is_admin_role(global_role) or is_academic_lead_role(global_role)))
            ],
            key=lambda item: parse_iso_utc(item.get("created_utc")) * -1,
        )

        institution_blocks.append(
            {
                "institution": _format_institution_row(institution, institution_memberships, visible_classes, flattened_assignments, flattened_submissions),
                "membership": membership,
                "permissions": {
                    "can_manage_billing": is_admin_role(global_role) or membership_role == "institution_admin",
                    "can_manage_members": _can_manage_members(global_role, membership_role),
                    "can_manage_classes": is_admin_role(global_role) or membership_role in CLASS_MANAGER_ROLES,
                    "can_create_assignments": is_admin_role(global_role) or membership_role in CLASS_MANAGER_ROLES,
                    "can_grade_submissions": is_admin_role(global_role) or membership_role in CLASS_MANAGER_ROLES,
                    "can_view_school_analytics": _can_view_all_classes(global_role, membership_role) or membership_role in {"teacher", "institution_admin"},
                    "can_participate_public_topics": public_topic_access,
                    "read_only": is_academic_lead_role(global_role) and not is_admin_role(global_role),
                },
                "members": {
                    "institution_admins": [
                        {"uid": row.get("uid"), "email": row.get("email"), "display_name": row.get("display_name"), "role": row.get("role"), "status": row.get("status")}
                        for row in institution_memberships
                        if _normalize_membership_role(row.get("role")) == "institution_admin"
                    ],
                    "teachers": [
                        {"uid": row.get("uid"), "email": row.get("email"), "display_name": row.get("display_name"), "role": row.get("role"), "status": row.get("status")}
                        for row in institution_memberships
                        if _normalize_membership_role(row.get("role")) == "teacher"
                    ],
                    "students": [
                        {"uid": row.get("uid"), "email": row.get("email"), "display_name": row.get("display_name"), "role": row.get("role"), "status": row.get("status")}
                        for row in institution_memberships
                        if _normalize_membership_role(row.get("role")) == "student"
                    ],
                }
                if _can_view_all_classes(global_role, membership_role) or membership_role in {"teacher", "institution_admin"}
                else {"institution_admins": [], "teachers": [], "students": []},
                "classes": visible_classes,
                "recent_assignments": flattened_assignments[:12],
                "recent_submissions": flattened_submissions[:20],
                "discussions": scoped_discussions[:20],
            }
        )

    public_topic_discussions = sorted(
        [
            {
                "id": row.get("id"),
                "scope": row.get("scope"),
                "institution_id": row.get("institution_id"),
                "title": row.get("title"),
                "body": row.get("body"),
                "module_id": row.get("module_id"),
                "created_by_uid": row.get("created_by_uid"),
                "created_by_role": row.get("created_by_role"),
                "created_utc": row.get("created_utc"),
            }
            for row in discussions
            if str(row.get("scope") or "").lower() == "public_topic" and public_topic_access
        ],
        key=lambda item: parse_iso_utc(item.get("created_utc")) * -1,
    )[:20]

    return {
        "ok": True,
        "viewer": {
            "uid": user_uid,
            "role": global_role,
            "is_admin": is_admin_role(global_role),
            "is_academic_lead": is_academic_lead_role(global_role) and not is_admin_role(global_role),
            "can_create_institutions": is_admin_role(global_role),
            "can_access_public_topics": public_topic_access,
        },
        "global_summary": {
            "institution_count": len(visible_institutions),
            "class_count": sum(len(block.get("classes", [])) for block in institution_blocks),
            "assignment_count": sum(int((block.get("institution") or {}).get("assignment_count") or 0) for block in institution_blocks),
            "pending_grading_count": sum(int((block.get("institution") or {}).get("pending_grading_count") or 0) for block in institution_blocks),
        },
        "public_topic_discussions": public_topic_discussions,
        "institutions": institution_blocks,
    }


def create_institution(user: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    global_role = normalize_role((user or {}).get("role"))
    if not is_admin_role(global_role):
        raise HTTPException(status_code=403, detail="Only platform admins can create institutions.")

    institution_name = _string(payload.get("name"))
    if not institution_name:
        raise HTTPException(status_code=400, detail="Institution name is required.")

    committed_student_seats = max(1, int(payload.get("committed_student_seats") or 1))
    seat_band = _seat_band_for_size(committed_student_seats)
    now_iso = _utc_now_iso()
    institution_id = _doc_id("inst")
    row = {
        "name": institution_name,
        "slug": _slugify(payload.get("slug") or institution_name),
        "committed_student_seats": committed_student_seats,
        "contract_start_utc": _string(payload.get("contract_start_utc")),
        "contract_end_utc": _string(payload.get("contract_end_utc")),
        "public_community_enabled": payload.get("public_community_enabled") is True,
        "status": _string(payload.get("status")) or "active",
        "seat_band_code": seat_band["code"],
        "created_utc": now_iso,
        "updated_utc": now_iso,
        "created_by_uid": _string((user or {}).get("uid")),
    }
    return _write_document(INSTITUTIONS_COLLECTION, institution_id, row)


def create_membership(user: Dict[str, Any], institution_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    global_role = normalize_role((user or {}).get("role"))
    user_uid = _string((user or {}).get("uid")) or ""
    institution = _document_payload(INSTITUTIONS_COLLECTION, institution_id)
    if not institution:
        raise HTTPException(status_code=404, detail="Institution not found.")

    memberships = _collection_items(MEMBERSHIPS_COLLECTION)
    viewer_membership = _member_record(memberships, user_uid, institution_id)
    viewer_membership_role = _normalize_membership_role((viewer_membership or {}).get("role"))

    target_uid = _string(payload.get("uid"))
    target_role = _normalize_membership_role(payload.get("role"))
    if not target_uid:
        raise HTTPException(status_code=400, detail="uid is required.")

    if not _can_manage_members(global_role, viewer_membership_role, target_role):
        raise HTTPException(status_code=403, detail="You do not have permission to manage this institution roster.")

    doc_id = _membership_doc_id(institution_id, target_uid)
    now_iso = _utc_now_iso()
    row = {
        "institution_id": institution_id,
        "uid": target_uid,
        "role": target_role,
        "email": _string(payload.get("email")),
        "display_name": _string(payload.get("display_name")),
        "status": _string(payload.get("status")) or "active",
        "created_utc": now_iso,
        "updated_utc": now_iso,
        "created_by_uid": user_uid,
    }
    return _write_document(MEMBERSHIPS_COLLECTION, doc_id, row)


def create_class(user: Dict[str, Any], institution_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    global_role = normalize_role((user or {}).get("role"))
    user_uid = _string((user or {}).get("uid")) or ""
    institution = _document_payload(INSTITUTIONS_COLLECTION, institution_id)
    if not institution:
        raise HTTPException(status_code=404, detail="Institution not found.")

    memberships = _collection_items(MEMBERSHIPS_COLLECTION)
    viewer_membership = _member_record(memberships, user_uid, institution_id)
    membership_role = _normalize_membership_role((viewer_membership or {}).get("role"))
    if not (is_admin_role(global_role) or membership_role in CLASS_MANAGER_ROLES):
        raise HTTPException(status_code=403, detail="You do not have permission to create classes for this institution.")

    name = _string(payload.get("name"))
    if not name:
        raise HTTPException(status_code=400, detail="Class name is required.")

    teacher_uids = safe_list_str(payload.get("teacher_uids"), max_items=20, max_len=128)
    if membership_role == "teacher" and user_uid not in teacher_uids:
        teacher_uids.insert(0, user_uid)
    student_uids = safe_list_str(payload.get("student_uids"), max_items=4000, max_len=128)
    now_iso = _utc_now_iso()
    class_id = _doc_id("class")
    join_code = (_string(payload.get("join_code")) or secrets.token_hex(3)).upper()[:12]
    row = {
        "institution_id": institution_id,
        "name": name,
        "term": _string(payload.get("term")),
        "teacher_uids": teacher_uids,
        "student_uids": student_uids,
        "topic_focus": _string(payload.get("topic_focus")),
        "join_code": join_code,
        "status": _string(payload.get("status")) or "active",
        "created_utc": now_iso,
        "updated_utc": now_iso,
        "created_by_uid": user_uid,
    }
    return _write_document(CLASSES_COLLECTION, class_id, row)


def create_assignment(user: Dict[str, Any], institution_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    global_role = normalize_role((user or {}).get("role"))
    user_uid = _string((user or {}).get("uid")) or ""
    class_id = _string(payload.get("class_id"))
    if not class_id:
        raise HTTPException(status_code=400, detail="class_id is required.")

    class_row = _document_payload(CLASSES_COLLECTION, class_id)
    if not class_row or _string(class_row.get("institution_id")) != institution_id:
        raise HTTPException(status_code=404, detail="Class not found for this institution.")

    memberships = _collection_items(MEMBERSHIPS_COLLECTION)
    viewer_membership = _member_record(memberships, user_uid, institution_id)
    membership_role = _normalize_membership_role((viewer_membership or {}).get("role"))
    if not _can_manage_class(global_role, membership_role, class_row, user_uid):
        raise HTTPException(status_code=403, detail="You do not have permission to assign work for this class.")

    title = _string(payload.get("title"))
    instructions = _string(payload.get("instructions"))
    if not title or not instructions:
        raise HTTPException(status_code=400, detail="Assignment title and instructions are required.")

    assignment_id = _doc_id("assign")
    now_iso = _utc_now_iso()
    resource_module_ids = [
        module_id
        for module_id in [normalize_module_id(item) for item in safe_list_str(payload.get("resource_module_ids"), max_items=20, max_len=24)]
        if module_id
    ]
    row = {
        "institution_id": institution_id,
        "class_id": class_id,
        "title": title,
        "assignment_type": _string(payload.get("assignment_type")) or "platform_resource",
        "instructions": instructions,
        "due_utc": _string(payload.get("due_utc")),
        "grading_mode": _string(payload.get("grading_mode")) or "manual",
        "resource_module_ids": resource_module_ids,
        "resource_titles": safe_list_str(payload.get("resource_titles"), max_items=20, max_len=140),
        "external_resource_url": _string(payload.get("external_resource_url")),
        "allow_resubmission": payload.get("allow_resubmission") is not False,
        "status": _string(payload.get("status")) or "published",
        "created_utc": now_iso,
        "updated_utc": now_iso,
        "created_by_uid": user_uid,
    }
    return _write_document(ASSIGNMENTS_COLLECTION, assignment_id, row)


def upsert_submission(user: Dict[str, Any], assignment_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    global_role = normalize_role((user or {}).get("role"))
    user_uid = _string((user or {}).get("uid")) or ""
    if global_role != "student":
        raise HTTPException(status_code=403, detail="Only student accounts can submit assignment work.")

    assignment_row = _document_payload(ASSIGNMENTS_COLLECTION, assignment_id)
    if not assignment_row:
        raise HTTPException(status_code=404, detail="Assignment not found.")

    class_row = _document_payload(CLASSES_COLLECTION, _string(assignment_row.get("class_id")) or "")
    if not class_row:
        raise HTTPException(status_code=404, detail="Class not found for this assignment.")

    institution_id = _string(assignment_row.get("institution_id")) or ""
    memberships = _collection_items(MEMBERSHIPS_COLLECTION)
    membership = _member_record(memberships, user_uid, institution_id)
    membership_role = _normalize_membership_role((membership or {}).get("role"))
    if membership_role != "student" or not _student_can_view_class(class_row, user_uid):
        raise HTTPException(status_code=403, detail="You are not enrolled in this class.")

    now_iso = _utc_now_iso()
    submission_id = f"{assignment_id}:{user_uid}"
    current = _document_payload(SUBMISSIONS_COLLECTION, submission_id)
    if current and current.get("status") == "graded" and assignment_row.get("allow_resubmission") is False:
        raise HTTPException(status_code=409, detail="This assignment does not allow resubmission.")

    text_response = _string(payload.get("text_response"))
    link_url = _string(payload.get("link_url"))
    attachment_names = safe_list_str(payload.get("attachment_names"), max_items=20, max_len=160)
    if not text_response and not link_url and not attachment_names:
        raise HTTPException(status_code=400, detail="Add a written response, a link, or at least one attachment name.")

    row = {
        "institution_id": institution_id,
        "class_id": _string(assignment_row.get("class_id")),
        "assignment_id": assignment_id,
        "student_uid": user_uid,
        "student_email": _string((user or {}).get("email")),
        "status": "submitted",
        "text_response": text_response,
        "link_url": link_url,
        "attachment_names": attachment_names,
        "submitted_utc": now_iso,
        "updated_utc": now_iso,
    }
    return _write_document(SUBMISSIONS_COLLECTION, submission_id, row)


def grade_submission(user: Dict[str, Any], submission_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    global_role = normalize_role((user or {}).get("role"))
    user_uid = _string((user or {}).get("uid")) or ""
    submission_row = _document_payload(SUBMISSIONS_COLLECTION, submission_id)
    if not submission_row:
        raise HTTPException(status_code=404, detail="Submission not found.")

    institution_id = _string(submission_row.get("institution_id")) or ""
    class_row = _document_payload(CLASSES_COLLECTION, _string(submission_row.get("class_id")) or "")
    memberships = _collection_items(MEMBERSHIPS_COLLECTION)
    viewer_membership = _member_record(memberships, user_uid, institution_id)
    membership_role = _normalize_membership_role((viewer_membership or {}).get("role"))
    if not _can_manage_class(global_role, membership_role, class_row, user_uid):
        raise HTTPException(status_code=403, detail="You do not have permission to grade this submission.")

    now_iso = _utc_now_iso()
    row = {
        "status": _string(payload.get("status")) or "graded",
        "score": payload.get("score"),
        "feedback": _string(payload.get("feedback")),
        "feedback_utc": now_iso,
        "graded_by_uid": user_uid,
        "updated_utc": now_iso,
    }
    return _write_document(SUBMISSIONS_COLLECTION, submission_id, row)


def create_discussion(user: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    global_role = normalize_role((user or {}).get("role"))
    user_uid = _string((user or {}).get("uid")) or ""
    scope = _string(payload.get("scope")) or ""
    title = _string(payload.get("title"))
    body = _string(payload.get("body"))
    if not title or not body:
        raise HTTPException(status_code=400, detail="Discussion title and body are required.")

    institution_id = _string(payload.get("institution_id"))
    class_id = _string(payload.get("class_id"))
    module_id = normalize_module_id(payload.get("module_id"))
    memberships = _collection_items(MEMBERSHIPS_COLLECTION)
    membership = _member_record(memberships, user_uid, institution_id or "")
    membership_role = _normalize_membership_role((membership or {}).get("role"))

    if scope == "public_topic":
        workspace = build_institutions_workspace(user)
        if not ((workspace.get("viewer") or {}).get("can_access_public_topics") or is_admin_role(global_role) or is_academic_lead_role(global_role)):
            raise HTTPException(status_code=403, detail="Public topic discussions are disabled for this account context.")
    elif scope == "institution":
        if not institution_id or not (membership or is_admin_role(global_role) or is_academic_lead_role(global_role)):
            raise HTTPException(status_code=403, detail="You do not have access to create an institution discussion here.")
    elif scope == "class":
        class_row = _document_payload(CLASSES_COLLECTION, class_id or "")
        if not class_row:
            raise HTTPException(status_code=404, detail="Class not found.")
        institution_id = _string(class_row.get("institution_id"))
        membership = _member_record(memberships, user_uid, institution_id or "")
        membership_role = _normalize_membership_role((membership or {}).get("role"))
        if not (
            is_admin_role(global_role)
            or is_academic_lead_role(global_role)
            or _can_manage_class(global_role, membership_role, class_row, user_uid)
            or (membership_role == "student" and _student_can_view_class(class_row, user_uid))
        ):
            raise HTTPException(status_code=403, detail="You do not have access to create a discussion for this class.")
    else:
        raise HTTPException(status_code=400, detail="Unsupported discussion scope.")

    discussion_id = _doc_id("disc")
    now_iso = _utc_now_iso()
    row = {
        "scope": scope,
        "institution_id": institution_id,
        "class_id": class_id,
        "module_id": module_id or None,
        "title": title,
        "body": body,
        "created_by_uid": user_uid,
        "created_by_role": membership_role if membership else global_role,
        "created_utc": now_iso,
        "updated_utc": now_iso,
    }
    return _write_document(DISCUSSIONS_COLLECTION, discussion_id, row)
