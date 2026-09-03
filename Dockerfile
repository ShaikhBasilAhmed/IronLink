# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Non-root, least-privilege runtime.
RUN useradd --create-home --uid 10001 appuser
WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY gunicorn.conf.py ./

USER appuser
EXPOSE 8443

# Container-level healthcheck hits readiness (has a valid signed pin set to serve).
# Scheme (http/https) is picked at runtime from whether TLS_CERT_FILE/TLS_KEY_FILE are
# set — this is a loopback check so we skip hostname/cert verification (the cert's CN/SAN
# is for the public hostname, not 127.0.0.1).
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD python -c "\
import os,ssl,urllib.request,sys; \
scheme='https' if os.getenv('TLS_CERT_FILE') and os.getenv('TLS_KEY_FILE') else 'http'; \
ctx=ssl._create_unverified_context() if scheme=='https' else None; \
sys.exit(0 if urllib.request.urlopen(f'{scheme}://127.0.0.1:8443/readyz',timeout=2,context=ctx).status==200 else 1)"

CMD ["gunicorn", "-c", "gunicorn.conf.py", "app.main:app"]
