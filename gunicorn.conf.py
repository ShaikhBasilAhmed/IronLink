"""Gunicorn config for the IronLink service (ASGI via uvicorn workers).

Run:  gunicorn -c gunicorn.conf.py app.main:app

TLS: gunicorn terminates TLS at the listening socket (worker-class agnostic), so
setting certfile/keyfile here works with UvicornWorker. This is the service's own
HTTPS transport cert — NOT the ECDSA pin-signing key (that lives in Vault and is
used inside the response, not for the socket).
"""
import multiprocessing
import os

bind = f"{os.getenv('LISTEN_HOST', '0.0.0.0')}:{os.getenv('LISTEN_PORT', '8443')}"

# --- TLS (optional) ---
# Leave both unset to serve plain HTTP (typical when a reverse proxy / LB in front
# already terminates TLS). Set both to have gunicorn terminate TLS directly.
# Key must be an UNENCRYPTED PEM (no passphrase) — restrict with file permissions
# instead (see README §6.2).
_certfile = os.getenv("TLS_CERT_FILE", "").strip()
_keyfile = os.getenv("TLS_KEY_FILE", "").strip()

if _certfile and _keyfile:
    certfile = _certfile
    keyfile = _keyfile

# CPU-bound work here is negligible (one ECDSA sign per rotation, then cache hits),
# so a modest worker count is plenty. Default: 2*cores + 1, capped/overridable.
_default_workers = min(2 * multiprocessing.cpu_count() + 1, 9)
workers = int(os.getenv("WEB_CONCURRENCY", _default_workers))
worker_class = "uvicorn.workers.UvicornWorker"

# Each worker keeps its own in-memory signed-response cache (independent refresh).
timeout = 30
graceful_timeout = 30
keepalive = 15               # keep-alive helps behind Cloudflare
max_requests = 20000         # periodic recycle to bound memory
max_requests_jitter = 2000
preload_app = False          # keep False: each worker owns its Vault client + refresher

accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info").lower()
