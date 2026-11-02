# syntax=docker/dockerfile:1
ARG XRAY_IMAGE=ghcr.io/xtls/xray-core:26.10.31@sha256:ceabeac03a89d991d2a247361825c1d1d2e9c91cd5dc010f298c7dc0c2f325c9
FROM ${XRAY_IMAGE} AS xray
FROM python:3.12-alpine
LABEL org.opencontainers.image.title="MikroTik Proxy Manager" \
      org.opencontainers.image.description="Xray VPN and selective routing management for MikroTik"
RUN apk add --no-cache ca-certificates curl iproute2 \
    && addgroup -g 10001 panel && adduser -D -u 10001 -G panel panel \
    && mkdir /data && chown panel:panel /data
COPY --from=xray /usr/local/bin/xray /usr/local/bin/xray
WORKDIR /app
COPY app/ /app/
COPY LICENSE THIRD_PARTY_NOTICES.md /usr/share/licenses/router-proxy-panel/
ENV APP_DATA=/data PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8080 1080 8443
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s CMD python -c "import os,socket; socket.create_connection(('127.0.0.1',int(os.getenv('PORT','8080'))),3).close()"
ENTRYPOINT ["python", "/app/entrypoint.py"]
