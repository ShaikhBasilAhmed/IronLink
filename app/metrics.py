"""Prometheus metrics. For multi-worker gunicorn, set PROMETHEUS_MULTIPROC_DIR
so /metrics aggregates across workers (see README)."""
from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

REQUESTS = Counter("ironlink_get_pins_requests_total", "GET /get-pins requests", ["result"])
# outcome: updated | unchanged | vault_error | parse_error
CACHE_REFRESH = Counter("ironlink_cache_refresh_total", "Signed-cache refreshes", ["outcome"])
VAULT_ERRORS = Counter("ironlink_vault_errors_total", "Vault operation failures")
SIGN_LATENCY = Histogram("ironlink_sign_seconds", "Time to build+sign a pin set")
CACHE_AGE = Gauge("ironlink_cache_age_seconds", "Age of the currently cached signed response")
READY = Gauge("ironlink_ready", "1 if the service has a valid signed response to serve")
