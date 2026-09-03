"""Parity tests:

1. app/certs.py::parse_cert_pem reproduces the openssl pipeline
       openssl x509 -pubkey -noout | openssl pkey -pubin -outform der
         | openssl dgst -sha256 -binary | openssl enc -base64
   exactly (verified against a real openssl-computed SPKI hash where openssl is
   available; otherwise verified against a hand-computed reference hash).

2. A client holding ONLY the ECDSA P-256 public key verifies each platform's own
   `signature`, computed over the UTF-8 bytes of that platform's own `pins` string
   only — not a canonical serialization of the node or the whole `data` object.
   These tests also document (not just guard against regressing) the accepted
   trade-off that `host`/`notBefore`/`notAfter` are NOT covered by either
   signature — see app/signing.py's module docstring.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import shutil
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

from app.certs import parse_cert_pem
from app.signing import EcdsaP256Signer, build_signed_data


def _self_signed_pem(common_name: str, days_valid: int = 365) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM).decode("ascii")


# --------------------------- certs.py parity ---------------------------

def test_spki_hash_matches_openssl_pipeline():
    pem = _self_signed_pem("parity.example.com")
    info = parse_cert_pem(pem)
    assert info.spki_sha256_b64.startswith("sha256/")

    if shutil.which("openssl") is None:
        pytest.skip("openssl CLI not available in this environment")

    p1 = subprocess.run(["openssl", "x509", "-pubkey", "-noout"], input=pem.encode(),
                         capture_output=True, check=True)
    p2 = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "der"], input=p1.stdout,
                         capture_output=True, check=True)
    p3 = subprocess.run(["openssl", "dgst", "-sha256", "-binary"], input=p2.stdout,
                         capture_output=True, check=True)
    expected = "sha256/" + base64.b64encode(p3.stdout).decode()
    assert info.spki_sha256_b64 == expected


def test_spki_hash_matches_hand_computed_reference():
    # Same pipeline, computed independently (not via app/certs.py) to catch a bug
    # that would make both the implementation AND a naive test agree by accident.
    pem = _self_signed_pem("reference.example.com")
    cert = x509.load_pem_x509_certificate(pem.encode())
    spki_der = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    expected = "sha256/" + base64.b64encode(hashlib.sha256(spki_der).digest()).decode()
    assert parse_cert_pem(pem).spki_sha256_b64 == expected


def test_ios_value_is_base64_of_full_der_cert():
    pem = _self_signed_pem("ios.example.com")
    info = parse_cert_pem(pem)
    cert = x509.load_pem_x509_certificate(pem.encode())
    assert info.der_b64 == base64.b64encode(cert.public_bytes(Encoding.DER)).decode()


def test_not_before_after_come_from_the_certificate():
    pem = _self_signed_pem("dates.example.com", days_valid=30)
    cert = x509.load_pem_x509_certificate(pem.encode())
    info = parse_cert_pem(pem)
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    assert info.not_before == nb.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert info.not_after == na.strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------- response signing parity ---------------------------

def _verify_platform(pub, node: dict) -> None:
    """What the mobile app does per platform: verify `signature` over `pins` alone."""
    pub.verify(
        base64.b64decode(node["signature"]),
        node["pins"].encode("utf-8"),
        ec.ECDSA(hashes.SHA256()),
    )


def _make_response(priv):
    cert = parse_cert_pem(_self_signed_pem("current.example.com"))
    signer = EcdsaP256Signer(priv)
    data = build_signed_data(cert, "example.com", signer)
    return {"data": data, "alg": "ecdsa-p256-sha256"}


def test_two_platform_response_has_per_platform_signatures_and_no_legacy_fields():
    priv = ec.generate_private_key(ec.SECP256R1())
    resp = _make_response(priv)
    data = resp["data"]

    assert data["host"] == "example.com"
    assert "signature" not in resp  # no top-level signature anymore
    assert "pinSetVersion" not in data
    assert "signingKeyId" not in data
    assert "issuedAt" not in data

    # Exactly one pin per platform — no old/new pair — plus its own signature.
    assert isinstance(data["android"]["pins"], str)
    assert isinstance(data["ios"]["pins"], str)
    assert data["android"]["pins"].startswith("sha256/")
    base64.b64decode(data["ios"]["pins"])  # iOS value decodes to valid DER bytes

    for platform in ("android", "ios"):
        assert set(data[platform]) == {"pins", "notBefore", "notAfter", "signature"}

    _verify_platform(priv.public_key(), data["android"])
    _verify_platform(priv.public_key(), data["ios"])


def test_android_and_ios_signatures_are_independent():
    priv = ec.generate_private_key(ec.SECP256R1())
    resp = _make_response(priv)
    data = resp["data"]

    assert data["android"]["signature"] != data["ios"]["signature"]

    # Android's signature must NOT verify against iOS's pins, and vice versa —
    # each platform's signature is only ever valid for its own `pins` value.
    with pytest.raises(Exception):
        _verify_platform(priv.public_key(), {"pins": data["ios"]["pins"], "signature": data["android"]["signature"]})
    with pytest.raises(Exception):
        _verify_platform(priv.public_key(), {"pins": data["android"]["pins"], "signature": data["ios"]["signature"]})


def test_tampered_android_pin_rejected():
    priv = ec.generate_private_key(ec.SECP256R1())
    resp = _make_response(priv)
    resp["data"]["android"]["pins"] = "sha256/EVIL"
    with pytest.raises(Exception):
        _verify_platform(priv.public_key(), resp["data"]["android"])


def test_tampered_ios_pin_rejected():
    priv = ec.generate_private_key(ec.SECP256R1())
    resp = _make_response(priv)
    resp["data"]["ios"]["pins"] = "QVRUQUNLRVI="  # base64("ATTACKER")
    with pytest.raises(Exception):
        _verify_platform(priv.public_key(), resp["data"]["ios"])


def test_tampering_host_or_validity_window_does_not_invalidate_signature():
    """Documents the accepted trade-off (see app/signing.py docstring): only `pins`
    is signed, so `host`/`notBefore`/`notAfter` are unauthenticated. This test is
    expected to PASS verification despite the tampering — it exists to make that
    trade-off visible and intentional, not to catch a bug."""
    priv = ec.generate_private_key(ec.SECP256R1())
    resp = _make_response(priv)
    resp["data"]["host"] = "evil.example.com"
    resp["data"]["android"]["notAfter"] = "2099-01-01T00:00:00Z"
    _verify_platform(priv.public_key(), resp["data"]["android"])  # does not raise


def test_key_loads_pem_der_raw():
    k = ec.generate_private_key(ec.SECP256R1())
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption()).decode()
    der = base64.b64encode(k.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption())).decode()
    raw = base64.b64encode(k.private_numbers().private_value.to_bytes(32, "big")).decode()
    for v in (pem, der, der + "\n", raw):
        s = EcdsaP256Signer.from_secret(v)
        assert len(base64.b64decode(s.sign(b"x"))) > 0
