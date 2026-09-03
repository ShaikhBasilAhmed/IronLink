"""Security response headers + client IP (behind Cloudflare)."""
from __future__ import annotations

from starlette.types import ASGIApp, Receive, Scope, Send


class SecurityHeadersMiddleware:
    HEADERS = [
        (b"strict-transport-security", b"max-age=63072000; includeSubDomains; preload"),
        (b"x-content-type-options", b"nosniff"),
        (b"x-frame-options", b"DENY"),
        (b"content-security-policy", b"default-src 'none'"),
        (b"referrer-policy", b"no-referrer"),
    ]

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                headers.extend(self.HEADERS)
            await send(message)

        await self.app(scope, receive, send_wrapper)


def client_ip(request) -> str:
    """Trust CF-Connecting-IP (set by Cloudflare); fall back to peer address."""
    return request.headers.get("CF-Connecting-IP") or (
        request.client.host if request.client else "unknown"
    )
