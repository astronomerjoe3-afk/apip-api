from __future__ import annotations

from typing import Iterable
from urllib.parse import urlparse

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.config import settings


LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
DEFAULT_APP_ORIGINS = (
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "https://127.0.0.1:3000",
    "https://localhost:3000",
)
DEFAULT_API_HOST_PATTERNS = ("127.0.0.1", "localhost", "*.run.app")
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
ORIGIN_GUARD_EXEMPT_PATHS = ("/billing/webhook",)


def _normalize_host(host: str) -> str:
    cleaned = host.strip().lower()
    if ":" in cleaned and not cleaned.startswith("["):
        return f"[{cleaned}]"
    return cleaned


def normalize_origin(value: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        raise ValueError("Origin must not be empty.")

    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Origin scheme must be http or https.")
    if not parsed.hostname:
        raise ValueError("Origin must include a hostname.")
    if parsed.username or parsed.password:
        raise ValueError("Origin must not include credentials.")
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("Origin must not include a path, query, or fragment.")

    hostname = parsed.hostname.lower()
    if parsed.scheme.lower() == "http" and hostname not in LOCAL_HOSTS:
        raise ValueError("Only local development origins may use plain HTTP.")

    port = parsed.port
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    netloc = _normalize_host(hostname)
    if port and port != default_port:
        netloc = f"{netloc}:{port}"

    return f"{parsed.scheme.lower()}://{netloc}"


def allowed_app_origins() -> list[str]:
    origins: set[str] = set()

    for value in DEFAULT_APP_ORIGINS:
        origins.add(normalize_origin(value))

    for raw in (settings.app_base_url, *(settings.allowed_app_origins.split(","))):
        candidate = str(raw or "").strip()
        if not candidate:
            continue
        origins.add(normalize_origin(candidate))

    return sorted(origins)


def trusted_api_hosts() -> list[str]:
    hosts: set[str] = set(DEFAULT_API_HOST_PATTERNS)

    api_hostname = settings.api_hostname
    if api_hostname:
        hosts.add(api_hostname)

    for raw in settings.allowed_api_hosts.split(","):
        candidate = str(raw or "").strip().lower()
        if candidate:
            hosts.add(candidate)

    return sorted(hosts)


def api_security_headers() -> dict[str, str]:
    headers = {
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
        "Cross-Origin-Resource-Policy": "same-site",
        "Cross-Origin-Opener-Policy": "same-origin",
    }

    if settings.is_production:
        headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"

    return headers


def is_allowed_browser_origin(origin: str) -> bool:
    try:
        normalized = normalize_origin(origin)
    except ValueError:
        return False
    return normalized in set(allowed_app_origins())


def _origin_from_referer(referer: str) -> str | None:
    candidate = str(referer or "").strip()
    if not candidate:
        return None

    parsed = urlparse(candidate)
    if not parsed.scheme or not parsed.hostname:
        return None

    try:
        return normalize_origin(f"{parsed.scheme}://{parsed.netloc}")
    except ValueError:
        return None


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        for key, value in api_security_headers().items():
            response.headers.setdefault(key, value)

        return response


class BrowserOriginGuardMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, exempt_paths: Iterable[str] = ORIGIN_GUARD_EXEMPT_PATHS):
        super().__init__(app)
        self._allowed_origins = set(allowed_app_origins())
        self._exempt_paths = tuple(exempt_paths)

    async def dispatch(self, request: Request, call_next):
        if request.method.upper() not in MUTATING_METHODS:
            return await call_next(request)

        if any(request.url.path.startswith(prefix) for prefix in self._exempt_paths):
            return await call_next(request)

        origin = request.headers.get("Origin")
        if origin:
            if origin not in self._allowed_origins and not is_allowed_browser_origin(origin):
                return JSONResponse({"detail": "Request origin is not allowed."}, status_code=403)
            return await call_next(request)

        referer_origin = _origin_from_referer(request.headers.get("Referer", ""))
        if referer_origin and referer_origin not in self._allowed_origins:
            return JSONResponse({"detail": "Request referer is not allowed."}, status_code=403)

        return await call_next(request)
