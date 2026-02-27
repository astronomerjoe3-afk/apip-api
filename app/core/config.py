from __future__ import annotations

import os
from dataclasses import dataclass


def _env(name: str, default: str | None = None) -> str | None:
    v = os.getenv(name)
    if v is None or v.strip() == "":
        return default
    return v.strip()


@dataclass(frozen=True)
class Settings:
    # Cloud / runtime
    google_cloud_project: str = _env("GOOGLE_CLOUD_PROJECT", "local") or "local"
    git_commit_sha: str = _env("GIT_COMMIT_SHA", "dev") or "dev"

    # App
    environment: str = _env("ENVIRONMENT", "dev") or "dev"
    service_name: str = _env("SERVICE_NAME", "apip-api") or "apip-api"

    # Security / operations
    # If you already enforce admin via Firebase custom claims, keep this False.
    # If you need an emergency break-glass for early ops, set to True and provide ADMIN_BEARER_TOKEN.
    enable_breakglass_admin_token: bool = (_env("ENABLE_BREAKGLASS_ADMIN_TOKEN", "false") or "false").lower() == "true"
    admin_bearer_token: str | None = _env("ADMIN_BEARER_TOKEN", None)


settings = Settings()