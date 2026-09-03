"""Certificate parsing: derive the Android and iOS pin material from a PEM cert.

Reproduces, in pure Python (no shelling out to `openssl` — avoids subprocess/
injection risk and works without the openssl CLI installed in the container),
the pipeline:

    openssl x509 -in cert.cer -pubkey -noout \
      | openssl pkey -pubin -outform der \
      | openssl dgst -sha256 -binary | openssl enc -base64

using `cryptography`, already a dependency.

Android pin  = "sha256/<base64 SHA-256 of the DER SubjectPublicKeyInfo>" (SPKI pin).
iOS value    = base64 of the full DER-encoded certificate.
Validity     = the certificate's own notBefore/notAfter (its X.509 fields), UTC.
"""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class CertInfo:
    """Derived, pin-relevant material for one certificate."""

    __slots__ = ("spki_sha256_b64", "der_b64", "not_before", "not_after")

    def __init__(self, spki_sha256_b64: str, der_b64: str, not_before: str, not_after: str) -> None:
        self.spki_sha256_b64 = spki_sha256_b64
        self.der_b64 = der_b64
        self.not_before = not_before
        self.not_after = not_after


def _fmt_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_cert_pem(pem_text: str) -> CertInfo:
    """Parse a PEM certificate and derive both platforms' pin material from it."""
    cert = x509.load_pem_x509_certificate(pem_text.encode("utf-8"))

    spki_der = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    spki_sha256_b64 = base64.b64encode(hashlib.sha256(spki_der).digest()).decode("ascii")

    cert_der_b64 = base64.b64encode(cert.public_bytes(Encoding.DER)).decode("ascii")

    # cryptography >=42 exposes tz-aware `*_utc` properties; fall back for older versions.
    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after

    return CertInfo(
        spki_sha256_b64=f"sha256/{spki_sha256_b64}",
        der_b64=cert_der_b64,
        not_before=_fmt_utc(not_before),
        not_after=_fmt_utc(not_after),
    )
