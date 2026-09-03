"""Vault client (hvac): AppRole auth with token renewal + retry, KV v2 reads.

Synchronous (hvac is sync). Callers should run these in a threadpool from async
code (see app/cache.py using asyncio.to_thread).
"""
from __future__ import annotations

import logging
import time

import hvac

logger = logging.getLogger("ironlink.vault")

# KV field name for the single active certificate. Fixed in code, not env-configurable
# (there is exactly one certificate field; nothing operationally varies this per-env).
CERT_FIELD = "cert"


class VaultError(Exception):
    """Internal Vault failure (logged server-side, never returned to the client)."""


class VaultClient:
    def __init__(
        self,
        addr: str,
        role_id: str,
        secret_id: str,
        kv_mount: str,
        secret_path: str,
        signing_key_field: str,
        cacert: str | None = None,
        skip_verify: bool = False,
        timeout: int = 5,
    ) -> None:
        verify: bool | str = False if skip_verify else (cacert or True)
        if skip_verify:
            logger.warning("VAULT_SKIP_VERIFY enabled — TLS verification OFF (dev only)")
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self._client = hvac.Client(url=addr, verify=verify, timeout=timeout)
        self._role_id = role_id
        self._secret_id = secret_id
        self._kv_mount = kv_mount
        self._secret_path = secret_path
        self._signing_key_field = signing_key_field
        self._token_expiry = 0.0  # monotonic seconds

    # --- auth ---
    def _login(self) -> None:
        try:
            resp = self._client.auth.approle.login(
                role_id=self._role_id, secret_id=self._secret_id
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("approle login failed: %s", exc)
            raise VaultError("approle login failed") from exc
        auth = resp.get("auth") or {}
        token = auth.get("client_token")
        if not token:
            raise VaultError("approle login returned no client_token")
        self._client.token = token
        lease = int(auth.get("lease_duration") or 0)
        # renew at 80% of lease; if no lease info, treat as short-lived (60s)
        self._token_expiry = time.monotonic() + max(30, int(lease * 0.8) if lease else 60)
        logger.info("approle login ok (lease=%ss)", lease)

    def _ensure_auth(self) -> None:
        if not self._client.token or time.monotonic() >= self._token_expiry:
            self._login()

    # --- reads ---
    def _read_kv(self, path: str) -> dict:
        last: Exception | None = None
        for attempt in (1, 2):
            try:
                self._ensure_auth()
                resp = self._client.secrets.kv.v2.read_secret_version(
                    path=path, mount_point=self._kv_mount, raise_on_deleted_version=True
                )
                return resp["data"]["data"]
            except Exception as exc:  # noqa: BLE001
                last = exc
                logger.warning("vault read attempt %d failed (%s): %s", attempt, path, exc)
                self._client.token = None  # force re-login next attempt
        logger.error("vault kv read failed (%s): %s", path, last)
        raise VaultError("kv read failed") from last

    def healthy(self) -> bool:
        try:
            self._ensure_auth()
            return bool(self._client.is_authenticated())
        except Exception:  # noqa: BLE001
            return False

    def fetch_cert(self) -> str:
        """Read the single active certificate (PEM text)."""
        data = self._read_kv(self._secret_path)

        cert = data.get(CERT_FIELD)
        if not cert or not str(cert).strip():
            raise VaultError(
                f"field {CERT_FIELD!r} missing/empty at {self._kv_mount}/{self._secret_path}"
            )
        return str(cert)

    def fetch_signing_key(self) -> str:
        data = self._read_kv(self._secret_path)
        value = data.get(self._signing_key_field)
        if not value or not str(value).strip():
            raise VaultError(
                f"signing key field {self._signing_key_field!r} missing/empty at "
                f"{self._kv_mount}/{self._secret_path}"
            )
        return str(value)
