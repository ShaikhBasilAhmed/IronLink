"""Print the signing PUBLIC key (P-256 SPKI DER, base64) — the value embedded in
the Android/iOS apps. Derived from the private key in Vault; the private key is
never printed.

    python scripts/show_pubkey.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.deps import get_signer  # noqa: E402


def main() -> int:
    print(get_signer().public_key_b64())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
