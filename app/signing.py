"""Per-platform ECDSA P-256 signing — each platform signs its own `pins` value only.

The response `data` object contains both platforms, each derived from the SAME
single active certificate (Vault field `cert`):

    {
      "host": "<str>",
      "android": { "pins": "sha256/...", "notBefore": "<rfc3339>", "notAfter": "<rfc3339>",
                    "signature": "<base64 DER ECDSA sig over the UTF-8 bytes of `pins`>" },
      "ios":     { "pins": "<base64 DER cert>", "notBefore": "<rfc3339>", "notAfter": "<rfc3339>",
                    "signature": "<base64 DER ECDSA sig over the UTF-8 bytes of `pins`>" }
    }

Android's pin is the SPKI SHA-256 hash; iOS's is the full DER certificate, base64
(see app/certs.py). There is exactly one pin per platform — no old/new pair, no
`issuedAt`, no `pinSetVersion`, no `signingKeyId`.

⚠️ WHAT IS SIGNED (deliberate, accepted trade-off — per explicit product-owner
instruction): each platform's `signature` covers ONLY the UTF-8 bytes of that
platform's `pins` string value, exactly as it appears in the JSON (for iOS, that is
the base64 *text*, not the decoded DER bytes) — NOT a canonical serialization of the
whole node or the whole `data` object. This means `host`, `notBefore`, and
`notAfter` are **not covered by any signature** — they are unauthenticated
plaintext. A captured, validly-signed `pins`+`signature` pair could be replayed
against a different `host`, or paired with an arbitrarily altered validity window,
without invalidating the signature. This was chosen specifically to remove the need
for any JSON canonicalization on the client (no key sorting, no separator rules —
the client verifies raw bytes it already has), at the cost of the host/validity
binding the previous whole-object scheme provided. See context.md / the RFC for the
full rationale and residual-risk note.

Client verification: for each platform, base64-decode `signature`, then verify it as
an ECDSA P-256 / SHA-256 DER signature over the UTF-8 bytes of that platform's own
`pins` string (nothing else — do not concatenate other fields in).

Signature: ECDSA P-256 over SHA-256, DER-encoded, then base64.
"""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from app.certs import CertInfo

ALG = "ecdsa-p256-sha256"


def build_signed_data(cert: CertInfo, host: str, signer: "EcdsaP256Signer") -> dict:
    android_pins = cert.spki_sha256_b64
    ios_pins = cert.der_b64
    return {
        "host": host,
        "android": {
            "pins": android_pins,
            "notBefore": cert.not_before,
            "notAfter": cert.not_after,
            "signature": signer.sign(android_pins.encode("utf-8")),
        },
        "ios": {
            "pins": ios_pins,
            "notBefore": cert.not_before,
            "notAfter": cert.not_after,
            "signature": signer.sign(ios_pins.encode("utf-8")),
        },
    }


def _require_ec(key) -> ec.EllipticCurvePrivateKey:
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("signing key is not an EC private key")
    if not isinstance(key.curve, ec.SECP256R1):
        raise ValueError(f"signing key curve is {key.curve.name}, expected secp256r1")
    return key


class EcdsaP256Signer:
    """Holds the ECDSA P-256 private key in memory; signs locally. Never logged."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        self._key = _require_ec(private_key)

    @classmethod
    def from_secret(cls, value: str) -> "EcdsaP256Signer":
        """Load from PEM (PKCS8/SEC1), base64/hex of DER, or a raw 32-byte scalar."""
        import re
        from cryptography.hazmat.primitives.serialization import (
            load_der_private_key,
            load_pem_private_key,
        )

        value = value.strip()
        if "PRIVATE KEY" in value:
            return cls(_require_ec(load_pem_private_key(value.encode(), password=None)))
        compact = "".join(value.split())
        raw = None
        if re.fullmatch(r"[0-9a-fA-F]+", compact) and len(compact) % 2 == 0:
            raw = bytes.fromhex(compact)
        else:
            padded = compact + "=" * (-len(compact) % 4)
            for dec in (base64.b64decode, base64.urlsafe_b64decode):
                try:
                    raw = dec(padded)
                    break
                except Exception:  # noqa: BLE001
                    continue
        if raw is None:
            raise ValueError("signing key is not PEM/base64/hex")
        if len(raw) == 32:
            return cls(ec.derive_private_key(int.from_bytes(raw, "big"), ec.SECP256R1()))
        return cls(_require_ec(load_der_private_key(raw, password=None)))

    def sign(self, data: bytes) -> str:
        return base64.b64encode(self._key.sign(data, ec.ECDSA(hashes.SHA256()))).decode("ascii")

    def public_key_b64(self) -> str:
        from cryptography.hazmat.primitives import serialization as ser
        der = self._key.public_key().public_bytes(
            ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(der).decode("ascii")
