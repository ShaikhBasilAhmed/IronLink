# IronLink

> Dynamic SSL/TLS certificate pin distribution for mobile apps — rotate
> certificates **without shipping an app release**, while keeping pinning
> protection intact.

[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Framework: FastAPI](https://img.shields.io/badge/Framework-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![Secrets: HashiCorp Vault](https://img.shields.io/badge/Secrets-HashiCorp_Vault-000000.svg)](https://www.vaultproject.io/)
[![CDN-Cacheable](https://img.shields.io/badge/Response-CDN--Cacheable-orange.svg)](#1-how-it-stays-cheap-at-scale)

- **Endpoint:** `GET /get-pins` → signed pin set (readable JSON; ECDSA P-256, DER+base64)
- **Trust:** the server signs with a private key in Vault; the app verifies with an
  **embedded public key**. No shared secret in the app. No nonce.
- **Scale:** the response is identical for all users and changes only on rotation,
  so it is fully cacheable at the CDN and (per worker) in memory. The origin performs
  **one signature per rotation**, then serves cache hits.

Certificate pinning is great for security and terrible for operations — a hardcoded
pin means every certificate rotation is an app release. IronLink moves the pin set
out of the app binary and behind a signed, CDN-cached endpoint, so rotation becomes
a config change instead of a release train, without giving up the guarantee that an
attacker can't just swap in their own certificate.

---

## Table of contents

1. [How it stays cheap at scale](#1-how-it-stays-cheap-at-scale)
2. [Prerequisites](#2-prerequisites)
3. [Configuration](#3-configuration)
4. [Vault setup](#4-vault-setup)
5. [Run](#5-run)
6. [TLS on the service's own listener](#6-tls-on-port-8443-this-services-own-https-listener)
7. [CDN configuration](#7-cdn-configuration-required-for-scale)
8. [Scale & capacity planning](#8-scale--capacity-planning)
9. [Certificate rotation runbook](#9-certificate-rotation-runbook)
10. [Observability](#10-observability)
11. [Security notes](#11-security-notes)
12. [Residual risks](#12-residual-risks-outside-this-services-control)
13. [Troubleshooting](#13-troubleshooting)
14. [Contributing](#contributing)
15. [License](#license)

---

## 1. How it stays cheap at scale

```
        Mobile apps ─┐
                     ▼
        CDN (WAF + edge cache)  ◄── serves ~all requests from cache
                     │  (cache MISS only: ~1 per POP per TTL per pin version)
                     ▼
        IronLink origin (this service)  ◄── in-memory signed-response cache
                     │  (Vault hit only on background refresh / rotation)
                     ▼
        HashiCorp Vault (KV v2: pins + signing key)
```

Two cache layers:
1. **CDN edge cache** — `GET /get-pins` returns `Cache-Control: public, max-age=…,
   stale-while-revalidate=…` and a stable `ETag`. Because the body is byte-identical
   between rotations, the CDN serves virtually every request from the edge.
2. **In-process cache** (per worker) — the origin fetches pins from Vault and signs
   **once**, then re-signs **only when the pin content changes**. A background task keeps
   it warm, so client requests never block on Vault. If Vault is briefly down, the last
   good response is served for `PIN_STALE_GRACE` seconds (stale-while-error).

Net effect: even a cache-bypass storm hits an in-memory byte buffer, not Vault or the CPU.
This is what lets a single small instance comfortably serve a large mobile fleet.

---

## 2. Prerequisites

| Requirement | Notes |
|---|---|
| Python **3.11+** (3.12 recommended) | Runtime |
| HashiCorp **Vault** (KV v2 + AppRole) | Stores the single active `cert` (PEM) and the ECDSA P-256 private key |
| A **CDN/WAF** in front (e.g. Cloudflare) | Required for the caching that makes this scale |
| Internal **CA bundle** (PEM) | If Vault uses an internal/self-signed cert (`VAULT_CACERT`) |
| Container runtime **or** systemd host | Docker/K8s or a VM |
| Prometheus (optional) | Scrapes `/metrics` |
| **TLS certificate + private key** (optional) | Only if this service terminates HTTPS itself on `LISTEN_PORT` (§6). Not needed if a reverse proxy / LB in front already terminates TLS. |

An **ECDSA P-256** key pair must already exist. The **private** key goes into Vault; the
**public** key is embedded in the Android/iOS apps (`scripts/show_pubkey.py` prints it).

---

## 3. Configuration

All via environment (see [.env.example](.env.example)). Secrets are injected at runtime,
never committed. Keep comments on their own lines in `.env`.

| Variable | Default | Purpose |
|---|---|---|
| `VAULT_ADDR` | — | Vault base URL |
| `VAULT_ROLE_ID` / `VAULT_SECRET_ID` | — | AppRole credentials (`SECRET_ID` sensitive) |
| `VAULT_CACERT` | (system trust) | PEM CA bundle for Vault TLS |
| `VAULT_SKIP_VERIFY` | `false` | **DEV ONLY** — disables TLS verification |
| `VAULT_TIMEOUT` | `5` | Seconds per Vault call (fail fast) |
| `VAULT_KV_MOUNT` / `VAULT_SECRET_PATH` | `secops` / `ironlink` | One secret holds both fields below |
| `VAULT_SIGNING_KEY_FIELD` | `ssl-signing-key` | ECDSA P-256 private key (PEM) |
| — | `cert` (fixed in code, not env-configurable — see `app/vault_client.py::CERT_FIELD`) | PEM certificate (the single active certificate) both platforms' pins are derived from |
| `PIN_HOST` | — | Host the pins apply to |
| `PIN_REFRESH_INTERVAL` | `30` | Background Vault refresh cadence (s) |
| `PIN_STALE_GRACE` | `3600` | Serve last-good this long if Vault is down (s) |
| `CDN_MAX_AGE` | `300` | `Cache-Control: max-age` sent to CDN/clients (s) |
| `CDN_STALE_WHILE_REVALIDATE` | `600` | `stale-while-revalidate` hint (s) |
| `RATE_LIMIT` | `120/minute` | Per-IP limit (origin only sees cache misses) |
| `WEB_CONCURRENCY` | auto | Gunicorn worker count |
| `LOG_LEVEL` | `INFO` | Log level |
| `METRICS_ENABLED` | `true` | Expose `/metrics` |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | (unset → plain HTTP) | This service's own HTTPS transport cert on `LISTEN_PORT` — see §6. **Not** the ECDSA pin-signing key. Key must be an unencrypted PEM. |

---

## 4. Vault setup

**Secret** at `secops/ironlink` (KV v2), **two fields**:

```jsonc
// cert             ->  PEM certificate (the single active certificate)
// ssl-signing-key  ->  ECDSA P-256 private key (PEM, or base64/DER)
```

`cert` is the **full PEM text** of the certificate (`-----BEGIN CERTIFICATE-----
...`), i.e. the same input your own `openssl x509 -in cert.cer ...` command takes.
IronLink derives **both platforms' pins from this one certificate directly** — you
do not compute or store SPKI hashes yourself:

- **Android** pin = SPKI SHA-256 hash, exactly reproducing:
  ```bash
  openssl x509 -in cert.cer -pubkey -noout | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary | openssl enc -base64
  ```
  (done in pure Python via `cryptography` — see `app/certs.py` — not by shelling
  out to `openssl`; a test asserts the two agree byte-for-byte).
- **iOS** value = base64 of the **full DER-encoded certificate**.
- `notBefore`/`notAfter` = that certificate's own X.509 validity fields.

```bash
vault kv patch -mount=secops ironlink cert=@cert.crt
vault kv patch -mount=secops ironlink ssl-signing-key=@signing_key.pem
```

> There is no `pinSetVersion` in the response — version-based rollback protection
> for this payload is intentionally out of scope here (handled by other means).
> `android` and `ios` are always derived from the same single `cert` and returned
> together in **one** signed response.
>
> ⚠️ **There is no old/new certificate pair.** Only the currently active
> certificate is ever pinned — there is no in-payload overlap window during a
> rotation. See §9 for what this means operationally and §11–§12 for the required
> mitigations (this is an explicit, accepted trade-off).

**Least-privilege policy** (read-only on that one secret):

```hcl
# ironlink-read.hcl
path "secops/data/ironlink" { capabilities = ["read"] }
```

```bash
vault policy write ironlink-read ironlink-read.hcl
vault auth enable approle   # if not already
vault write auth/approle/role/ironlink \
    token_policies="ironlink-read" token_ttl=1h token_max_ttl=4h \
    secret_id_ttl=90d secret_id_num_uses=0
vault read  auth/approle/role/ironlink/role-id
vault write -f auth/approle/role/ironlink/secret-id
```

---

## 5. Run

### Local (dev)
```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env        # fill in VAULT_* (and VAULT_CACERT)
uvicorn app.main:app --host 0.0.0.0 --port 8443
# with TLS (uvicorn's own flags — independent of TLS_CERT_FILE/TLS_KEY_FILE in .env):
uvicorn app.main:app --host 0.0.0.0 --port 8443 \
  --ssl-certfile /path/to/fullchain.pem --ssl-keyfile /path/to/privkey.pem
```

### Production (gunicorn + uvicorn workers)
```bash
gunicorn -c gunicorn.conf.py app.main:app
# TLS is picked up automatically from TLS_CERT_FILE / TLS_KEY_FILE in the environment
# (see §6) — no extra flags needed here.
```

### Docker
```bash
docker build -t ironlink-pin-service:1.0.0 .
docker run --rm -p 8443:8443 --env-file .env ironlink-pin-service:1.0.0
# or: docker compose up --build
```

### Verify
```bash
curl -s http://127.0.0.1:8443/get-pins | python -m json.tool
curl -si http://127.0.0.1:8443/get-pins | grep -i -E 'etag|cache-control'
curl -s  http://127.0.0.1:8443/healthz   # liveness
curl -s  http://127.0.0.1:8443/readyz    # readiness (has a valid signed set)
pytest -q                                # signing parity tests

# if TLS is enabled (§6), use https:// — add -k for a self-signed/local cert whose
# CN/SAN doesn't match 127.0.0.1, or --cacert <ca.pem> to verify properly:
curl -sk https://127.0.0.1:8443/readyz
```

### Public key for the apps
```bash
python scripts/show_pubkey.py    # P-256 SPKI DER, base64 -> embed in Android/iOS
```

### Response shape (both platforms, derived from the single active `cert`; each platform carries its OWN signature)
```json
{
  "data": {
    "host": "example.com",
    "android": {
      "pins": "sha256/8HHa2JKSpTbQmKIVvh2PXjZN2c7UUBbs5XdZyVjuZLU=",
      "notBefore": "2026-06-16T00:00:00Z",
      "notAfter": "2026-12-31T23:59:59Z",
      "signature": "<base64 DER ECDSA P-256 signature over the UTF-8 bytes of this platform's own `pins` string>"
    },
    "ios": {
      "pins": "<base64 DER of cert>",
      "notBefore": "2026-06-16T00:00:00Z",
      "notAfter": "2026-12-31T23:59:59Z",
      "signature": "<base64 DER ECDSA P-256 signature over the UTF-8 bytes of this platform's own `pins` string>"
    }
  },
  "alg": "ecdsa-p256-sha256"
}
```
The app reads its own node (`data.android` or `data.ios`) — a single `pins` string, not
an array. **Verification:** base64-decode `data.<platform>.signature` and verify it as an
ECDSA P-256 / SHA-256 DER signature over the **UTF-8 bytes of `data.<platform>.pins`
alone** (no JSON re-serialization, no other fields included) with the embedded public key.
There is **no top-level `signature`** field anymore — each platform's signature only ever
covers its own `pins` value.

⚠️ **Accepted trade-off:** because only `pins` is signed, `host`, `notBefore`, and
`notAfter` are **not covered by either signature** — they are unauthenticated plaintext.
This was chosen deliberately to remove the need for any client-side JSON canonicalization
(no key-sorting, no separator rules — the client verifies bytes it already has). See §11
for the full rationale and residual-risk note.

---

## 6. TLS on port 8443 (this service's own HTTPS listener)

You already have a certificate + private key for this service and want gunicorn to
terminate HTTPS directly on `LISTEN_PORT` (8443), rather than relying only on a
front-end proxy. This is a **different key from the ECDSA pin-signing key** in Vault:

| | Pin-signing key (Vault) | TLS cert/key (this section) |
|---|---|---|
| Purpose | Signs the pin payload **inside** the JSON response | Secures the **HTTPS transport** to reach the API at all |
| Lives in | HashiCorp Vault (`ssl-signing-key`) | On disk / mounted into the container or host |
| Type | ECDSA P-256 | Whatever CA issued it (RSA or EC) |
| Rotates via | Vault write + cache refresh (§9) | Normal TLS cert renewal (e.g. every 47–398 days per your CA) |

### 6.1 Configure

Set two environment variables (see [.env.example](.env.example)). `.crt`/`.key` files
work as-is — they're PEM, just with different extensions:

```bash
TLS_CERT_FILE=/etc/ironlink/tls/fullchain.crt   # leaf cert, or leaf+intermediates concatenated
TLS_KEY_FILE=/etc/ironlink/tls/privkey.key      # UNENCRYPTED private key (PEM)
```

Leave both unset to serve **plain HTTP** — the normal setup when a CDN or another
reverse proxy in front already terminates TLS. Setting both switches gunicorn to HTTPS
on `LISTEN_PORT`; `app/config.py` validates at startup that both files exist. The key
must be unencrypted (no passphrase) — gunicorn's `keyfile` setting has no way to supply
one; restrict access with file permissions instead (§6.2).

If your certificate is a bare leaf cert, concatenate the issuing chain so clients that
don't already trust the intermediate can still build a full chain:
```bash
cat leaf.crt intermediate.crt > fullchain.crt
```
Check first: `grep -c "BEGIN CERTIFICATE" your-cert.crt` — `1` means leaf-only (needs
the chain appended); `2+` means it's already a full chain.

### 6.2 File permissions (the part people get wrong)

The private key must be **readable by the service's own user**, and by no one else:

```bash
# bare-metal / systemd (runs as user "ironlink")
sudo chown ironlink:ironlink /etc/ironlink/tls/privkey.key
sudo chmod 400 /etc/ironlink/tls/privkey.key

# Docker: the image runs as uid 10001 ("appuser") — the HOST file must be readable
# by that uid (bind mounts preserve host permissions/ownership into the container)
sudo chown 10001:10001 /etc/ironlink/tls/privkey.key
sudo chmod 400 /etc/ironlink/tls/privkey.key
```
If you see gunicorn fail to bind with a permission error on `keyfile`, this is almost
always why — the container's non-root user can't read a `root`-owned, `600` file.

### 6.3 Docker / Compose

`docker-compose.yml` already includes example volume mounts:
```yaml
volumes:
  - /etc/ironlink/tls/fullchain.crt:/etc/ironlink/tls/fullchain.crt:ro
  - /etc/ironlink/tls/privkey.key:/etc/ironlink/tls/privkey.key:ro
```
Point `TLS_CERT_FILE` / `TLS_KEY_FILE` in `.env` at the **container-side** paths (the
right-hand side above), and apply the uid 10001 permissions from §6.2 to the **host**
files. The container `HEALTHCHECK` (and the compose `healthcheck:`) auto-detect HTTP vs
HTTPS from whether `TLS_CERT_FILE`/`TLS_KEY_FILE` are set, and skip certificate
verification for the loopback check (the cert's CN/SAN is for your public hostname, not
`127.0.0.1`).

### 6.4 CDN "Full (Strict)" mode

Terminating TLS at the origin is what lets you set your CDN's SSL/TLS mode to something
like Cloudflare's **Full (Strict)** (the CDN validates the origin certificate, not just
that *some* cert is present). Use a publicly-trusted cert (or a CDN-issued Origin CA
certificate) rather than a self-signed one if you want strict verification — otherwise
fall back to accepting self-signed certs and rely on the WAF/network boundary for origin
protection.

### 6.5 Renewal

This cert is independent of the certificate-rotation workflow in §9 (that's for the pins
*inside* the response). Track its expiry like any other server certificate — a lapsed TLS
cert here takes the whole `/get-pins` endpoint down, which is exactly the kind of outage
this project exists to prevent for the *mobile app's* certificate. Automate renewal
(ACME/cert-manager, or your CA's tooling) and reload/restart on renewal.

---

## 7. CDN configuration (required for scale)

Create a **Cache Rule** for the pin endpoint (shown here for Cloudflare; any CDN with
equivalent cache-key and TTL controls works):

- **When:** hostname = `ironlink.…` **and** URI path = `/get-pins`
- **Then:**
  - *Eligible for cache:* **Yes**
  - *Edge TTL:* **Respect origin** (honours our `Cache-Control: max-age`), or set explicitly (e.g. 300s)
  - *Browser TTL:* respect origin
  - *Cache key:* URL only — **ignore cookies and query string** (the response is identical for all users)
  - Enable tiered/hierarchical caching for better global hit ratio, if your CDN offers it
- Keep the **WAF** enabled; rate-limiting rules optional (origin already caches).
- On rotation, **purge** the cached `/get-pins` object (or wait out `max-age`) — see §9.

Do **not** vary the cache on any per-user header. There is no per-user data in the response.

---

## 8. Scale & capacity planning

**Workload shape.** The body is identical for everyone and changes only on rotation.

| Scenario | Origin QPS | CPU work |
|---|---|---|
| With CDN caching (expected) | a few req/min (edge misses + revalidations) | ~0 (serves a cached buffer) |
| CDN bypassed / cold, avg (illustrative, 3M-device fleet) | 3M refresh/day ÷ 86,400 ≈ **~35 rps** | serve in-memory buffer |
| CDN bypassed, login surge (~15×) | **~500–700 rps** | serve in-memory buffer |
| Rotation event | +1 Vault read + **2 signatures** (one per platform) per worker | sub-millisecond |

A single small instance serves thousands of req/s of a cached ~1 KB buffer. The origin
is **I/O-light and CPU-light**; run **≥2 instances for HA**, not for throughput.

**Recommended hardware (per instance):**

| Resource | Minimum | Recommended | Notes |
|---|---|---|---|
| vCPU | 1 | **2** | `WEB_CONCURRENCY≈2×cores`; work is trivial |
| RAM | 256 MB | **1–2 GB** | Stateless; cache is a few KB per worker |
| Disk | 1 GB | 5 GB | Stateless; logs ship out |
| Network | 100 Mbps | 1 Gbps | ~1 KB/response; negligible with CDN |

**Topology:** 2–4 instances behind a load balancer (or directly as CDN origins),
across ≥2 AZs. Autoscale on CPU/RPS is optional given the low load; scale mainly for
resilience. Vault should be its own HA cluster (existing infra) — this service only reads.

**Why not bigger?** The expensive operation (ECDSA signing) happens **once per rotation**,
not per request. Over-provisioning buys headroom for a misconfigured/purged cache, nothing more.

---

## 9. Certificate rotation runbook

*(pin content, not this service's own TLS cert — see §6.5)*

⚠️ Vault holds **exactly one active certificate** (`cert`) — there is **no old/new pair**
and **no in-payload overlap window**. A client must have fetched the new pin *before* the
certificate is actually cut over, or it will fail to pin against the new leaf until its
next successful `/get-pins` fetch. This is an explicit, accepted trade-off (see §11–§12).
The mitigation is entirely operational — get the new pin to every client with margin
before cutover:

1. Write the new certificate to `cert` **well ahead of** (at minimum several multiples of
   `PIN_REFRESH_INTERVAL` plus `CDN_MAX_AGE`, but in practice days, not minutes, ahead — to
   give the client-side app's own refresh cadence and offline/retry logic time to catch up)
   the actual TLS cutover.
2. Within `PIN_REFRESH_INTERVAL` the origin detects the change, re-parses the certificate,
   and re-signs — Android/iOS pins update automatically (see `app/certs.py`).
3. **Purge** the CDN cache for `/get-pins` immediately (do not wait `CDN_MAX_AGE`)
   so edges — and therefore clients — pick up the new pin as fast as possible.
4. Monitor client-side adoption (app-side telemetry/metrics on last-fetched pin, if
   available) before cutting over the certificate on your TLS-serving hosts.
5. Cut over the certificate only once you have confidence the fleet has had time to fetch
   the new pin. There is no fallback here if a client hasn't refreshed in time — pinning
   will fail for that client until its next successful fetch.
6. **Emergency rotation** (compromise): the safety margin above is not available — accept
   that some clients will fail to pin until they refresh; purge cache immediately and treat
   client-side pin failures as expected fallout, not a bug.

Guardrails: `cert` must always be a valid, parseable PEM certificate (the service fails to
update — and keeps serving the last-known-good response — if it fails to parse; see
`ironlink_cache_refresh_total{outcome="parse_error"}`). Consider a canary (a subset via a
separate path/host) before fleet-wide, and budget rotation lead time generously given there
is no overlap safety net.

---

## 10. Observability

| Endpoint | Use |
|---|---|
| `GET /healthz` | Liveness — process up (no Vault dependency). Use for LB/k8s liveness. |
| `GET /readyz` | Readiness — a valid signed set is available. Use for LB/k8s readiness. |
| `GET /metrics` | Prometheus metrics. |

Key metrics: `ironlink_get_pins_requests_total{result}`,
`ironlink_cache_refresh_total{outcome}` (outcome: `updated`|`unchanged`|`vault_error`|`parse_error`),
`ironlink_vault_errors_total`, `ironlink_cache_age_seconds`, `ironlink_ready`, `ironlink_sign_seconds`.

Suggested alerts:
- `ironlink_ready == 0` for > 1m (no serveable pins) — **page**.
- `rate(ironlink_vault_errors_total[5m]) > 0` sustained — Vault/auth problem.
- `rate(ironlink_cache_refresh_total{outcome="parse_error"}[5m]) > 0` — `cert` in Vault
  contains an unparseable certificate — **page** (a rotation write likely went wrong).
- `ironlink_cache_age_seconds > PIN_STALE_GRACE * 0.8` — refresh is failing.
- CDN cache hit-ratio for `/get-pins` drops — cache misconfig / purge storm.

**Multi-worker metrics:** with several gunicorn workers, set `PROMETHEUS_MULTIPROC_DIR`
to a writable dir so `/metrics` aggregates across workers; otherwise each worker reports
its own process. (systemd unit already allows `ReadWritePaths=…/prometheus_multiproc`.)

---

## 11. Security notes

- App holds only the **public** key; the private key stays in Vault and is read into
  memory to sign. A public key can verify but not create a signature.
- ⚠️ Storing the private key in **Vault KV** (vs the **Transit** engine) means the key
  enters process memory. For the strongest posture, use **Transit** (key never leaves
  Vault) and get security/compliance sign-off on key custody. This build uses KV per the
  current design.
- TLS to Vault is verified by default; provide `VAULT_CACERT`. `VAULT_SKIP_VERIFY` is dev-only.
- AppRole token is auto-renewed; policy is read-only on the single secret.
- Security headers (HSTS, nosniff, frame-deny, CSP `default-src 'none'`) on every response.
- Fail-safe: if no valid signed set exists, the API returns `503` rather than anything
  unverified; the app keeps its last-known-good pins.
- Outbound calls go only to Vault (your internal instance). Flag any unexpected egress in review.
- Keep the TLS private key (§6) file-permission-restricted (0400, owned by the service
  user only) even though it is a different asset from the pin-signing key.
- ⚠️ **Only `pins` is signed — `host`/`notBefore`/`notAfter` are unauthenticated
  plaintext.** Each platform's `signature` covers ONLY the UTF-8 bytes of that
  platform's own `pins` value (see the Response shape note above), not the whole
  node and not the whole `data` object. Concretely: a captured, validly-signed
  `pins`+`signature` pair could be replayed against a different `host`, or paired
  with an arbitrarily altered validity window, without invalidating the signature —
  there is no rollback/replay protection of any kind for this payload (this also
  supersedes what a `pinSetVersion` field would have protected against; there is no
  such field). This was chosen deliberately to remove the need for any client-side
  JSON canonicalization. Explicit, accepted trade-off — equivalent protection for
  `host`/validity/replay is expected to be provided elsewhere, out of scope of this
  service.
- ⚠️ There is no old/new certificate pair and no in-payload rollover overlap window —
  only the single active certificate is ever pinned. A client that hasn't refreshed
  before the certificate is rotated in Vault will fail to pin until its next successful
  fetch. This is an explicit, accepted trade-off, not an oversight — see §9 for the
  rotation runbook and required lead-time mitigation.

---

## 12. Residual risks (outside this service's control)

Pin **delivery** depends on user connectivity and third parties: telecom/ISP outages,
offline first launch, captive portals, DNS failure/blocking, CDN outages, stale edge
cache around a rotation, device clock skew, corporate MITM proxies. These can
cause **temporary, self-healing unavailability** — never a security downgrade. Mitigate on
the **client**: baked-in fallback pins for first-run/offline, background refresh with
retry/backoff well before expiry, and keep last-known-good pins.

---

## 13. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Startup: `STARTUP FAILED: could not build an initial signed pin set` | Vault unreachable, TLS (`VAULT_CACERT`), AppRole creds, or `secops/ironlink` missing `cert`/`ssl-signing-key`, or the cert fails to parse (check logs for the parse error). |
| `503 PINS_UNAVAILABLE` at runtime | Vault down beyond `PIN_STALE_GRACE`; the last-good response was dropped. Check `ironlink_vault_errors_total`. |
| Vault call hangs | Should not — `VAULT_TIMEOUT` bounds it. Confirm value is set. |
| TLS `CERTIFICATE_VERIFY_FAILED` to Vault | Set `VAULT_CACERT` to the internal CA bundle. (This is Vault's cert, unrelated to §6.) |
| Signature won't verify on device | The client must verify `data.<platform>.signature` over the **UTF-8 bytes of `data.<platform>.pins` alone** — not the whole node, not the whole `data` object, no JSON re-serialization (see `app/signing.py::build_signed_data`). A common mistake: verifying against the wrong platform's `pins` (e.g. iOS signature against Android's pins) — each signature only ever verifies against its own platform's `pins`. |
| Low CDN hit-ratio | Cache rule not matching `/get-pins`, or cache key varying on cookies/query. |
| Gunicorn: `PermissionError` / fails to bind on the TLS `keyfile` | Host-side key file isn't readable by the service user (systemd) or container uid 10001 (Docker). Fix ownership/permissions — see §6.2. |
| Gunicorn: SSL error binding, key looks fine | Key is password-protected — gunicorn cannot use an encrypted key. Re-export it unencrypted, e.g. `openssl rsa -in privkey.key -out privkey-unencrypted.key` (or `openssl ec -in ...` for an EC key), and restrict it with file permissions (§6.2) instead. |
| `ValueError: TLS_CERT_FILE path does not exist` at startup | Path is wrong for the process's own view of the filesystem — e.g. a host path given to a container that only sees the container-side mount path (§6.3). |
| Browser/CLI: "certificate not trusted" hitting the origin directly | Expected for a self-signed cert — either add `--cacert`/`-k` for local testing, or use a chain issued by a trusted/CDN Origin CA for real traffic (§6.4). |

---

## Contributing

Issues and pull requests are welcome. A few areas that would particularly benefit from
contributions:

- Support for Vault's **Transit** engine as an alternative to KV (keeps the signing key
  from ever entering process memory — see §11)
- A reference client-side verification snippet for Android (Kotlin) and iOS (Swift)
- Additional CDN examples beyond Cloudflare (Fastly, CloudFront, etc.)
- Structured/JSON logging output option

For anything non-trivial, please open an issue first to discuss the approach.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
