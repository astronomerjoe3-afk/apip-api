from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.audit import write_audit_log
from app.common import get_client_ip
from app.dependencies import require_authenticated_user
from app.schemas.institution import (
    InstitutionAssignmentCreateIn,
    InstitutionClassCreateIn,
    InstitutionCreateIn,
    InstitutionDiscussionCreateIn,
    InstitutionMembershipCreateIn,
    InstitutionSubmissionGradeIn,
    InstitutionSubmissionUpsertIn,
)
from app.services.institution_service import (
    build_institutions_workspace,
    create_assignment,
    create_class,
    create_discussion,
    create_institution,
    create_membership,
    grade_submission,
    upsert_submission,
)


router = APIRouter(prefix="/institutions", tags=["institutions"])


def _audit(request: Request, user: dict, event_type: str, path: str, details: dict, status: int = 200) -> None:
    write_audit_log(
        event_type=event_type,
        actor_uid=(user or {}).get("uid"),
        actor_email=(user or {}).get("email"),
        role=(user or {}).get("role"),
        path=path,
        method=request.method,
        status=status,
        request_id=getattr(request.state, "request_id", None),
        ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details=details,
    )


@router.get("/workspace")
def institutions_workspace(request: Request, user=Depends(require_authenticated_user)):
    workspace = build_institutions_workspace(user or {})
    _audit(
        request,
        user or {},
        event_type="institutions.workspace.read",
        path="/institutions/workspace",
        details={
            "institution_count": len(workspace.get("institutions") or []),
            "public_topic_count": len(workspace.get("public_topic_discussions") or []),
        },
    )
    return workspace


@router.post("")
def institutions_create(payload: InstitutionCreateIn, request: Request, user=Depends(require_authenticated_user)):
    row = create_institution(user or {}, payload.model_dump())
    _audit(
        request,
        user or {},
        event_type="institutions.create",
        path="/institutions",
        details={"institution_id": row.get("id"), "slug": row.get("slug")},
    )
    return {"ok": True, "institution": row}


@router.post("/{institution_id}/memberships")
def institutions_add_membership(
    institution_id: str,
    payload: InstitutionMembershipCreateIn,
    request: Request,
    user=Depends(require_authenticated_user),
):
    row = create_membership(user or {}, institution_id, payload.model_dump())
    _audit(
        request,
        user or {},
        event_type="institutions.membership.create",
        path=f"/institutions/{institution_id}/memberships",
        details={"institution_id": institution_id, "membership_id": row.get("id"), "target_uid": row.get("uid"), "target_role": row.get("role")},
    )
    return {"ok": True, "membership": row}


@router.post("/{institution_id}/classes")
def institutions_add_class(
    institution_id: str,
    payload: InstitutionClassCreateIn,
    request: Request,
    user=Depends(require_authenticated_user),
):
    row = create_class(user or {}, institution_id, payload.model_dump())
    _audit(
        request,
        user or {},
        event_type="institutions.class.create",
        path=f"/institutions/{institution_id}/classes",
        details={"institution_id": institution_id, "class_id": row.get("id"), "class_name": row.get("name")},
    )
    return {"ok": True, "class": row}


@router.post("/{institution_id}/assignments")
def institutions_add_assignment(
    institution_id: str,
    payload: InstitutionAssignmentCreateIn,
    request: Request,
    user=Depends(require_authenticated_user),
):
    row = create_assignment(user or {}, institution_id, payload.model_dump())
    _audit(
        request,
        user or {},
        event_type="institutions.assignment.create",
        path=f"/institutions/{institution_id}/assignments",
        details={"institution_id": institution_id, "assignment_id": row.get("id"), "class_id": row.get("class_id")},
    )
    return {"ok": True, "assignment": row}


@router.post("/assignments/{assignment_id}/submission")
def institutions_submit_assignment(
    assignment_id: str,
    payload: InstitutionSubmissionUpsertIn,
    request: Request,
    user=Depends(require_authenticated_user),
):
    row = upsert_submission(user or {}, assignment_id, payload.model_dump())
    _audit(
        request,
        user or {},
        event_type="institutions.submission.upsert",
        path=f"/institutions/assignments/{assignment_id}/submission",
        details={"assignment_id": assignment_id, "submission_id": row.get("id")},
    )
    return {"ok": True, "submission": row}


@router.post("/submissions/{submission_id}/grade")
def institutions_grade_submission(
    submission_id: str,
    payload: InstitutionSubmissionGradeIn,
    request: Request,
    user=Depends(require_authenticated_user),
):
    row = grade_submission(user or {}, submission_id, payload.model_dump())
    _audit(
        request,
        user or {},
        event_type="institutions.submission.grade",
        path=f"/institutions/submissions/{submission_id}/grade",
        details={"submission_id": submission_id, "status": row.get("status"), "score": row.get("score")},
    )
    return {"ok": True, "submission": row}


@router.post("/discussions")
def institutions_add_discussion(
    payload: InstitutionDiscussionCreateIn,
    request: Request,
    user=Depends(require_authenticated_user),
):
    row = create_discussion(user or {}, payload.model_dump())
    _audit(
        request,
        user or {},
        event_type="institutions.discussion.create",
        path="/institutions/discussions",
        details={"discussion_id": row.get("id"), "scope": row.get("scope"), "institution_id": row.get("institution_id"), "class_id": row.get("class_id")},
    )
    return {"ok": True, "discussion": row}
