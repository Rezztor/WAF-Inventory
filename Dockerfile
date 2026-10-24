# syntax=docker/dockerfile:1
FROM python:3.13-slim@sha256:d98cc29d3266e535dd9da1099688d9cb3ca4753813571e071763d17725460962

RUN useradd --system --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin waf \
 && install -d -o 10001 -g 10001 -m 0700 /data
COPY pyproject.toml README.md /src/
COPY src /src/src
RUN pip install --no-cache-dir /src && rm -rf /src

ENV WAF_INV_CONFIG=/data/config.toml WAF_INV_TLS_DIR=/data/tls PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
WORKDIR /data
VOLUME /data
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --start-interval=2s CMD ["python", "-c", "import ssl, urllib.request as u; u.urlopen('https://127.0.0.1:8443/healthz', context=ssl._create_unverified_context(), timeout=4)"]
CMD ["waf-inv", "serve", "--host", "0.0.0.0", "--port", "8443"]
