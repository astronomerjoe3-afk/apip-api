from __future__ import annotations

from functools import lru_cache
from google.cloud import firestore

from app.core.config import settings


@lru_cache(maxsize=1)
def get_firestore_client() -> firestore.Client:
    # GOOGLE_CLOUD_PROJECT is the canonical project id in Cloud Run.
    # For local dev, default is "local" (see config) which still works if you set credentials/emulator.
    return firestore.Client(project=settings.google_cloud_project)