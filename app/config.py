"""Configuration — all values from environment / injected secrets.

No secret is hardcoded. VAULT_SECRET_ID is sensitive and is injected at runtime
(Vault Agent / Kubernetes secret / systemd EnvironmentFile with 0600 perms).
"""
from __future__ import annotations

import os

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="", case_sensitive=True, env_file=".env", extra="ignore"
    )

    # --- Vault connection (AppRole auth, KV v2) ---
    VAULT_ADDR: str
    VAULT_ROLE_ID: str
    VAULT_SECRET_ID: str = Field(repr=False)
    VAULT_CACERT: str | None = None            # PEM CA bundle for TLS verification
    VAULT_SKIP_VERIFY: bool = False            # DEV ONLY — never true in production
    VAULT_TIMEOUT: int = 5                       # seconds per Vault call

    # --- KV v2 layout ---
    # One secret holds both fields: the signing key and the single active certificate.
    # There is no old/new pair — only the currently active certificate is pinned.
    # The certificate field name itself is fixed in code (app/vault_client.py::CERT_FIELD),
    # not env-configurable — only the signing-key field name varies per environment.
    VAULT_KV_MOUNT: str = "secops"
    VAULT_SECRET_PATH: str = "ironlink"
    VAULT_SIGNING_KEY_FIELD: str = "ssl-signing-key"

    # --- Protocol ---
    PIN_HOST: str

    # --- Caching / scale ---
    # In-process signed-response cache. Response is re-signed ONLY when pin content
    # changes, so it stays byte-identical (CDN-cacheable) between rotations.
    PIN_REFRESH_INTERVAL: int = 30              # background refresh cadence (s)
    PIN_STALE_GRACE: int = 3600                 # serve last-good this long if Vault is down (s)
    CDN_MAX_AGE: int = 300                      # Cache-Control max-age sent to Cloudflare/clients (s)
    CDN_STALE_WHILE_REVALIDATE: int = 600       # stale-while-revalidate hint (s)

    # --- Service ---
    LISTEN_HOST: str = "0.0.0.0"
    LISTEN_PORT: int = 8443
    RATE_LIMIT: str = "120/minute"             # per-IP (origin only sees CDN cache misses)
    METRICS_ENABLED: bool = True
    LOG_LEVEL: str = "INFO"

    # --- TLS (this service's own HTTPS listener on LISTEN_PORT) ---
    # NOT the ECDSA pin-signing key — this is the transport cert (e.g. so Cloudflare can
    # run "Full (Strict)" mode to the origin, or so the port can be exposed directly).
    # If TLS_CERT_FILE/TLS_KEY_FILE are unset, the app serves plain HTTP (typical when a
    # reverse proxy / load balancer in front already terminates TLS).
    TLS_CERT_FILE: str | None = None           # PEM: leaf cert, or full chain (leaf+intermediates)
    TLS_KEY_FILE: str | None = None            # PEM: unencrypted private key (0600, service-user readable only)

    @field_validator(
        "VAULT_CACERT", "TLS_CERT_FILE", "TLS_KEY_FILE", mode="before"
    )
    @classmethod
    def _normalize_optional_path(cls, v):
        # Treat blank / whitespace / a leftover inline comment as "unset".
        if v is None:
            return None
        v = str(v).strip()
        if not v or v.startswith("#"):
            return None
        return v

    @field_validator("VAULT_CACERT", "TLS_CERT_FILE", "TLS_KEY_FILE")
    @classmethod
    def _path_must_exist(cls, v, info):
        if v and not os.path.isfile(v):
            raise ValueError(f"{info.field_name} path does not exist: {v!r}")
        return v

    @property
    def tls_enabled(self) -> bool:
        return bool(self.TLS_CERT_FILE and self.TLS_KEY_FILE)


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
