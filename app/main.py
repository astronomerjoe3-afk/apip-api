from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import app.routers.admin_ops as admin_ops
import app.routers.catalog as catalog
import app.routers.debug_text as debug_text
import app.routers.instructor as instructor
import app.routers.progress as progress
import app.routers.student_progression as student_progression
import app.routers.student_runner as student_runner
import app.routers.system as system
from app.middleware.request_id import RequestIDMiddleware

app = FastAPI(title="APIP API", version="0.5.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
app.include_router(debug_text.router)
app.include_router(student_progression.router)
app.include_router(student_runner.router)
