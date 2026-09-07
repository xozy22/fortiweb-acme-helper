FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    ACME_HELPER_CONFIG=/config/config.yaml \
    ACME_HELPER_DATA=/data

RUN groupadd -g 1000 acme && useradd -u 1000 -g acme -m acme \
    && mkdir -p /data /config \
    && chown -R acme:acme /data /config

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install .

USER acme
VOLUME ["/data", "/config"]

ENTRYPOINT ["acme-helper"]
CMD ["run"]
