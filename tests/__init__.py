from __future__ import annotations

import sys
import types


def _install_fastapi_stub() -> None:
    try:
        __import__("fastapi")
        return
    except ModuleNotFoundError:
        pass

    fastapi_module = types.ModuleType("fastapi")

    class Request:  # pragma: no cover - test import shim only
        headers: dict
        client: object | None

    fastapi_module.Request = Request
    sys.modules["fastapi"] = fastapi_module


def _install_google_stub() -> None:
    try:
        __import__("google.cloud.firestore")
        __import__("google.auth.exceptions")
        return
    except ModuleNotFoundError:
        pass

    google_module = sys.modules.setdefault("google", types.ModuleType("google"))

    cloud_module = types.ModuleType("google.cloud")
    firestore_module = types.ModuleType("google.cloud.firestore")
    auth_module = types.ModuleType("google.auth")
    auth_exceptions_module = types.ModuleType("google.auth.exceptions")

    class DefaultCredentialsError(Exception):
        pass

    class FieldFilter:  # pragma: no cover - test import shim only
        def __init__(self, field: str, op: str, value: object) -> None:
            self.field = field
            self.op = op
            self.value = value

    class Query:  # pragma: no cover - test import shim only
        ASCENDING = "ASCENDING"

    class Client:  # pragma: no cover - test import shim only
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

    class DocumentSnapshot:  # pragma: no cover - test import shim only
        id = ""

        def to_dict(self) -> dict:
            return {}

        @property
        def exists(self) -> bool:
            return False

    firestore_module.FieldFilter = FieldFilter
    firestore_module.Query = Query
    firestore_module.Client = Client
    firestore_module.DocumentSnapshot = DocumentSnapshot
    auth_exceptions_module.DefaultCredentialsError = DefaultCredentialsError

    google_module.cloud = cloud_module
    google_module.auth = auth_module
    cloud_module.firestore = firestore_module
    auth_module.exceptions = auth_exceptions_module

    sys.modules["google.cloud"] = cloud_module
    sys.modules["google.cloud.firestore"] = firestore_module
    sys.modules["google.auth"] = auth_module
    sys.modules["google.auth.exceptions"] = auth_exceptions_module


_install_fastapi_stub()
_install_google_stub()
