from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _load_local_env_file() -> None:
    repo_root = Path(__file__).resolve().parents[2]

    for filename in (".env.local", ".env"):
        env_path = repo_root / filename
        if not env_path.exists():
            continue

        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("\"'")
            if key and key not in os.environ:
                os.environ[key] = value


_load_local_env_file()


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
    app_base_url: str = _env("APP_BASE_URL", "https://app.cognispark.tech") or "https://app.cognispark.tech"
    allowed_app_origins: str = _env("ALLOWED_APP_ORIGINS", "") or ""

    # Security / operations
    # If you already enforce admin via Firebase custom claims, keep this False.
    # If you need an emergency break-glass for early ops, set to True and provide ADMIN_BEARER_TOKEN.
    enable_breakglass_admin_token: bool = (_env("ENABLE_BREAKGLASS_ADMIN_TOKEN", "false") or "false").lower() == "true"
    admin_bearer_token: str | None = _env("ADMIN_BEARER_TOKEN", None)
    enable_local_dev_student: bool = (_env("ENABLE_LOCAL_DEV_STUDENT", "false") or "false").lower() == "true"
    local_dev_student_uid: str = _env("LOCAL_DEV_STUDENT_UID", "local-student") or "local-student"
    local_dev_student_email: str = _env("LOCAL_DEV_STUDENT_EMAIL", "student@local.dev") or "student@local.dev"

    # Billing
    stripe_secret_key: str | None = _env("STRIPE_SECRET_KEY", None)
    stripe_webhook_secret: str | None = _env("STRIPE_WEBHOOK_SECRET", None)
    stripe_price_module_unlock_default: str | None = _env("STRIPE_PRICE_MODULE_UNLOCK_DEFAULT", None)
    stripe_price_premium_monthly: str | None = _env("STRIPE_PRICE_PREMIUM_MONTHLY", None)
    stripe_price_premium_six_month: str | None = _env("STRIPE_PRICE_PREMIUM_SIX_MONTH", None)
    stripe_price_premium_yearly: str | None = _env("STRIPE_PRICE_PREMIUM_YEARLY", None)


settings = Settings()
