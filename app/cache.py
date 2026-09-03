"""In-process signed-response cache — the core scale mechanism.

The /get-pins response is identical for every user and changes ONLY when the
certificate changes. So we:
  * fetch the single active cert from Vault + sign ONCE, keep the serialized
    response in memory,
  * re-sign ONLY when the certificate content actually changes (stable
    signature between refreshes -> byte-identical response -> highly
    CDN-cacheable),
  * refresh in the background so requests never block on Vault,
  * serve last-known-good (stale) if Vault is temporarily unavailable.

This keeps the origin trivially loaded even behind millions of users.

NOTE: there is no old/new certificate overlap — only the current certificate is
ever pinned. A client that hasn't refreshed before the certificate is rotated in
Vault will fail to pin until its next successful fetch. This is an accepted,
explicit trade-off (see context.md / RFC residual risks) — the mitigation is
refresh cadence + CDN cache invalidation on rotation, not a payload-level overlap.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time

from app.certs import parse_cert_pem
from app.metrics import CACHE_REFRESH, READY, SIGN_LATENCY, VAULT_ERRORS
from app.signing import ALG, EcdsaP256Signer, build_signed_data
from app.vault_client import VaultClient, VaultError

logger = logging.getLogger("ironlink.cache")


class SignedResponseCache:
    def __init__(self, vault: VaultClient, signer: EcdsaP256Signer, host: str,
                 stale_grace: int) -> None:
        self._vault = vault
        self._signer = signer
        self._host = host
        self._stale_grace = stale_grace
        self._lock = asyncio.Lock()

        self._body: bytes | None = None      # serialized JSON response
        self._etag: str | None = None
        self._content_key: str | None = None  # cert_pem
        self._built_at: float = 0.0          # monotonic
        self._last_ok: float = 0.0           # monotonic

    @property
    def ready(self) -> bool:
        return self._body is not None

    def snapshot(self) -> tuple[bytes, str] | None:
        if self._body is None or self._etag is None:
            return None
        return self._body, self._etag

    def age_seconds(self) -> float:
        return time.monotonic() - self._built_at if self._body else -1.0

    async def refresh(self) -> None:
        """Fetch + (re)sign if the certificates changed. Safe under concurrency."""
        async with self._lock:
            try:
                cert_pem = await asyncio.to_thread(self._vault.fetch_cert)
            except VaultError:
                VAULT_ERRORS.inc()
                CACHE_REFRESH.labels(outcome="vault_error").inc()
                self._maybe_expire_stale()
                return

            # Unchanged cert -> keep the existing signature (stable, cacheable).
            content_key = cert_pem
            if content_key == self._content_key and self._body is not None:
                self._last_ok = time.monotonic()
                CACHE_REFRESH.labels(outcome="unchanged").inc()
                return

            try:
                cert = parse_cert_pem(cert_pem)
            except Exception as exc:  # noqa: BLE001
                logger.error("failed to parse certificate from Vault: %s", exc)
                CACHE_REFRESH.labels(outcome="parse_error").inc()
                self._maybe_expire_stale()
                return

            with SIGN_LATENCY.time():
                data = build_signed_data(cert, self._host, self._signer)

            body = json.dumps(
                {"data": data, "alg": ALG},
                separators=(",", ":"), ensure_ascii=False,
            ).encode("utf-8")
            etag = 'W/"%s"' % hashlib.sha256(body).hexdigest()[:16]

            self._body = body
            self._etag = etag
            self._content_key = content_key
            self._built_at = time.monotonic()
            self._last_ok = self._built_at
            READY.set(1)
            CACHE_REFRESH.labels(outcome="updated").inc()
            logger.info(
                "signed response refreshed",
                extra={
                    "certFingerprint": hashlib.sha256(cert_pem.encode()).hexdigest()[:12],
                },
            )

    def _maybe_expire_stale(self) -> None:
        """Drop the cached response if Vault has been down beyond the grace window."""
        if self._body is None:
            return
        if time.monotonic() - self._last_ok > self._stale_grace:
            logger.error("stale grace exceeded (%ss) — dropping cached pins", self._stale_grace)
            self._body = None
            self._etag = None
            self._content_key = None
            READY.set(0)


async def run_refresher(cache: SignedResponseCache, interval: int, stop: asyncio.Event) -> None:
    """Background loop: keep the cache warm so requests never wait on Vault."""
    while not stop.is_set():
        try:
            await cache.refresh()
        except Exception as exc:  # noqa: BLE001
            logger.error("refresher error: %s", exc)
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
