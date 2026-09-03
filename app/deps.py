"""Singletons: Vault client and the ECDSA signer (private key loaded once)."""
from __future__ import annotations

from functools import lru_cache

from app.config import get_settings
from app.signing import EcdsaP256Signer
from app.vault_client import VaultClient


@lru_cache(maxsize=1)
def get_vault_client() -> VaultClient:
    s = get_settings()
    return VaultClient(
        addr=s.VAULT_ADDR,
        role_id=s.VAULT_ROLE_ID,
        secret_id=s.VAULT_SECRET_ID,
        kv_mount=s.VAULT_KV_MOUNT,
        secret_path=s.VAULT_SECRET_PATH,
        signing_key_field=s.VAULT_SIGNING_KEY_FIELD,
        cacert=s.VAULT_CACERT,
        skip_verify=s.VAULT_SKIP_VERIFY,
        timeout=s.VAULT_TIMEOUT,
    )


@lru_cache(maxsize=1)
def get_signer() -> EcdsaP256Signer:
    value = get_vault_client().fetch_signing_key()
    return EcdsaP256Signer.from_secret(value)
