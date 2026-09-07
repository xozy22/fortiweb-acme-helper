FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    ACME_HELPER_CONFIG=/config/config.yaml \
    ACME_HELPER_DATA=/data \
    PUID=1000 \
    PGID=1000

# gosu: Rechte nach dem chown der Volumes abgeben (PUID/PGID, Unraid-Konvention)
RUN apt-get update \
    && apt-get install -y --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 acme && useradd -u 1000 -g acme -m acme \
    && mkdir -p /data /config \
    && chown -R acme:acme /data /config

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install .

COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

VOLUME ["/data", "/config"]

LABEL org.opencontainers.image.title="acme-helper" \
      org.opencontainers.image.description="Unofficial ACME DNS-01 automation for FortiWeb (Cloudflare, do.de, Strato). Not affiliated with Fortinet." \
      org.opencontainers.image.source="https://github.com/xozy22/fortiweb-acme-helper" \
      org.opencontainers.image.licenses="MIT"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["run"]
