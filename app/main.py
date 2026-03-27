from __future__ import annotations

import threading

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

import app.routers.admin_ops as admin_ops
import app.routers.auth as auth_router
import app.routers.billing as billing
import app.routers.catalog as catalog
import app.routers.debug_text as debug_text
import app.routers.instructor as instructor
import app.routers.progress as progress
import app.routers.student_support as student_support
import app.routers.student_progression as student_progression
import app.routers.student_runner as student_runner
import app.routers.system as system
from app.core.config import settings
from app.middleware.request_id import RequestIDMiddleware
from app.security import BrowserOriginGuardMiddleware, allowed_app_origins, trusted_api_hosts, SecurityHeadersMiddleware
from app.services.catalog_bootstrap import ensure_catalog_seeded
from app.services.monetization_service import ensure_monetization_seeded

docs_url = "/docs" if settings.expose_api_docs else None
openapi_url = "/openapi.json" if settings.expose_api_docs else None
redoc_url = "/redoc" if settings.expose_api_docs else None

app = FastAPI(
    title="APIP API",
    version="0.5.0",
    docs_url=docs_url,
    openapi_url=openapi_url,
    redoc_url=redoc_url,
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=trusted_api_hosts(),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_app_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "Origin", "X-API-Key", "X-Request-Id"],
)

app.add_middleware(BrowserOriginGuardMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
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
app.include_router(auth_router.router)
app.include_router(catalog.router)
app.include_router(billing.router)
app.include_router(instructor.router)
app.include_router(admin_ops.router)
app.include_router(progress.router)
app.include_router(student_support.router)
if settings.expose_debug_routes:
    app.include_router(debug_text.router)
app.include_router(student_progression.router)
app.include_router(student_runner.router)
