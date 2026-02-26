import os
from typing import Any, Dict, Optional

import firebase_admin
from firebase_admin import auth, credentials


# -------------------------------------------------------
# Firebase Admin initialization (idempotent)
# -------------------------------------------------------

def init_firebase_admin() -> None:
    """
    Ensures firebase_admin is initialized exactly once.

    In Cloud Run, application default credentials are available.
    Locally, you can use GOOGLE_APPLICATION_CREDENTIALS or gcloud auth application-default login.
    """
    if firebase_admin._apps:
        return

    # If a service account JSON path is provided, use it.
    sa_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    if sa_path:
        cred = credentials.Certificate(sa_path)
        firebase_admin.initialize_app(cred)
        return

    # Otherwise rely on Application Default Credentials.
    firebase_admin.initialize_app()


def verify_id_token(id_token: str, *, check_revoked: bool = False) -> Dict[str, Any]:
    """
    Verifies Firebase ID token and returns decoded claims.

    NOTE: This verifies signature and standard claims.
    Custom claims like 'role' will be present if you set them on the user.
    """
    init_firebase_admin()
    return auth.verify_id_token(id_token, check_revoked=check_revoked)