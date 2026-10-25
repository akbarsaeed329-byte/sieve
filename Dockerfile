FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SIEVE_BIND_HOST=0.0.0.0

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Install Python deps first (cache layer)
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e ".[dev]"

# App source
COPY sieve ./sieve
COPY config ./config
COPY integrations ./integrations

RUN adduser --disabled-password --gecos '' sieve && \
    chown -R sieve:sieve /app
USER sieve

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8080/api/health || exit 1

CMD ["sieve", "serve"]
