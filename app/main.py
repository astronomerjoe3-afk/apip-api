from __future__ import annotations

import threading

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import app.routers.admin_ops as admin_ops
import app.routers.billing as billing
import app.routers.catalog as catalog
import app.routers.debug_text as debug_text
import app.routers.instructor as instructor
import app.routers.progress as progress
import app.routers.student_progression as student_progression
import app.routers.student_runner as student_runner
import app.routers.system as system
from app.core.config import settings
from app.middleware.request_id import RequestIDMiddleware
from app.services.catalog_bootstrap import ensure_catalog_seeded
from app.services.monetization_service import ensure_monetization_seeded


def _allowed_origins() -> list[str]:
    origins = {
        "http://127.0.0.1:3000",
        "http://localhost:3000",
        "https://127.0.0.1:3000",
        "https://localhost:3000",
    }

    app_base_url = str(settings.app_base_url or "").strip().rstrip("/")
    if app_base_url:
        origins.add(app_base_url)

    for raw in str(settings.allowed_app_origins or "").split(","):
        origin = str(raw or "").strip().rstrip("/")
        if origin:
            origins.add(origin)

    return sorted(origins)


app = FastAPI(title="APIP API", version="0.5.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(RequestIDMiddleware)


def _bootstrap_services_worker() -> None:
    try:
        seeded = ensure_catalog_seeded()
        if seeded:
            print("Catalog bootstrap: seeded curriculum content into Firestore.")
    except Exception as exc:
        print(f"Catalog bootstrap skipped: {exc}")

    try:
        monetization_seeded = ensure_monetization_seeded()
        if monetization_seeded:
            print("Monetization bootstrap: seeded launch pricing into Firestore.")
    except Exception as exc:
        print(f"Monetization bootstrap skipped: {exc}")


@app.on_event("startup")
def bootstrap_services() -> None:
    # Do not block the web server from binding to PORT on Cloud Run while
    # optional Firestore bootstrap work completes.
    threading.Thread(target=_bootstrap_services_worker, daemon=True).start()


app.include_router(system.router)
app.include_router(catalog.router)
app.include_router(billing.router)
app.include_router(instructor.router)
app.include_router(admin_ops.router)
app.include_router(progress.router)
app.include_router(debug_text.router)
app.include_router(student_progression.router)
app.include_router(student_runner.router)
