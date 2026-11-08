FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install . \
    && useradd --system --no-create-home --uid 10001 pcaplab \
    && install -d -o pcaplab /data

# Captures are read from /data (a volume or a bind mount) and reports are written there. The program only reads files,
# so it runs as an unprivileged user, with a read-only root filesystem, no capabilities and no network at all.
USER pcaplab
WORKDIR /data
VOLUME ["/data"]
ENTRYPOINT ["pcaplab"]
CMD ["--help"]
