"""Pydantic models.

The response carries BOTH platforms in one payload, derived from the single active
certificate stored in Vault, but each platform carries its OWN signature:
    data = { host,
              android: { pins: "sha256/...", notBefore, notAfter, signature },
              ios:     { pins: "<base64 DER cert>", notBefore, notAfter, signature } }
`notBefore`/`notAfter` are that certificate's own validity window. Each platform's
`signature` covers ONLY the UTF-8 bytes of that platform's own `pins` string — not
the whole node, not the whole `data` object (see app/signing.py::build_signed_data).
There is no top-level `signature` field anymore.

⚠️ Because only `pins` is signed, `host`/`notBefore`/`notAfter` are unauthenticated
plaintext — a captured `pins`+`signature` pair could be replayed against a different
host or an altered validity window without breaking the signature. This was chosen
to remove the need for any client-side JSON canonicalization. Explicit, accepted
trade-off — see context.md / the RFC for the residual-risk note.

There is no `pinSetVersion` and no `signingKeyId` — out of scope of this service.
There is also no old/new pin pair and no `issuedAt`: only the current certificate
is ever pinned, so there is no in-payload rollover overlap window. This is an
explicit, accepted trade-off — see context.md / the RFC for the residual-risk note.
"""
from __future__ import annotations

from pydantic import BaseModel


class ErrorResponse(BaseModel):
    error: str
    code: str
