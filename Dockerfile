# ---- web build (SvelteKit static) ----
FROM node:26-slim AS web
WORKDIR /web
COPY sieve/web/package.json sieve/web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY sieve/web/ ./
RUN npm run build

# ---- runtime ----
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SIEVE_BIND_HOST=0.0.0.0 SIEVE_DATA_DIR=/app/data
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/* \
 && adduser --disabled-password --gecos '' --uid 10001 sieve
COPY pyproject.toml README.md ./
COPY sieve ./sieve
RUN rm -rf sieve/web/node_modules sieve/web/build
COPY --from=web /web/build ./sieve/web/build
RUN pip install --no-cache-dir . && mkdir -p /app/data && chown sieve:sieve /app/data
COPY config ./config
COPY integrations ./integrations
USER sieve
EXPOSE 8080
VOLUME ["/app/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://localhost:8080/api/health || exit 1
CMD ["sieve", "serve"]
