from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import app.routers.admin_ops as admin_ops
import app.routers.catalog as catalog
import app.routers.instructor as instructor
import app.routers.progress as progress
import app.routers.system as system
from app.middleware.request_id import RequestIDMiddleware

app = FastAPI(title="APIP API", version="0.4.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: env allowlist later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(RequestIDMiddleware)

app.include_router(system.router)
app.include_router(catalog.router)
app.include_router(instructor.router)
app.include_router(admin_ops.router)
app.include_router(progress.router)
