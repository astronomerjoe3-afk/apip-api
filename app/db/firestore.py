from __future__ import annotations

import os
from typing import Optional

from google.cloud import firestore
from google.auth.exceptions import DefaultCredentialsError

from app.core.config import settings

_firestore_client: Optional[firestore.Client] = None


def _detect_project() -> Optional[str]:
    """
    Resolve the GCP project ID.
    Priority:
      1) settings.google_cloud_project (if not local/empty)
      2) env vars (GOOGLE_CLOUD_PROJECT, GCP_PROJECT, GCLOUD_PROJECT)
      3) None (let google-auth infer project if possible)
    """
    p = getattr(settings, "google_cloud_project", None)
    if p and str(p).strip().lower() not in ("", "local", "none"):
        return str(p).strip()

    for k in ("GOOGLE_CLOUD_PROJECT", "GCP_PROJECT", "GCLOUD_PROJECT"):
        v = os.getenv(k)
        if v and str(v).strip():
            return str(v).strip()

    return None


def _sanitize_google_application_credentials_env() -> None:
    """
    If GOOGLE_APPLICATION_CREDENTIALS is set but points to a missing file,
    google-auth will fail hard and won't fall back to ADC (gcloud).
    We remove it for the current process so ADC can work.
    """
    gac = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    if not gac:
        return

    gac = str(gac).strip().strip('"')
    if not gac:
        return

    # Only sanitize when it is clearly unusable.
    if not os.path.exists(gac):
        os.environ.pop("GOOGLE_APPLICATION_CREDENTIALS", None)


def get_firestore_client() -> firestore.Client:
    """
    Singleton Firestore client. Supports:
      - Local dev with GOOGLE_APPLICATION_CREDENTIALS -> service account JSON
      - Local dev with `gcloud auth application-default login` (ADC)
      - Cloud Run / GCE / GKE ADC

    Important: If GOOGLE_APPLICATION_CREDENTIALS is set to a non-existent path,
    we unset it for the process so ADC can still succeed.
    """
    global _firestore_client
    if _firestore_client is not None:
        return _firestore_client

    _sanitize_google_application_credentials_env()
    project = _detect_project()

    try:
        _firestore_client = firestore.Client(project=project) if project else firestore.Client()
        return _firestore_client
    except DefaultCredentialsError as e:
        raise RuntimeError(
            "Firestore credentials not found.\n"
            "- If using a service account JSON, set GOOGLE_APPLICATION_CREDENTIALS to a valid file path.\n"
            "- Or run: `gcloud auth application-default login`\n"
            "- If GOOGLE_APPLICATION_CREDENTIALS is set globally to a missing file, remove/unset it.\n"
        ) from e

    return _firestore_client
