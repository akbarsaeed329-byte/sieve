.PHONY: help setup dev web demo test lint bench up up-ai down logs token clean
help:            ## Show targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'
setup:           ## Create config/sieve.yaml and .env from the examples (keeps existing files)
	@test -f config/sieve.yaml || cp config/sieve.example.yaml config/sieve.yaml
	@test -f .env || cp .env.example .env
	@echo "Edit config/sieve.yaml and .env, then run 'make up' or 'make dev'."
web:             ## Build the web app into sieve/web/build (needs Node 20+)
	cd sieve/web && npm ci --no-audit --no-fund && npm run build
dev: setup       ## Run locally with Python (no Docker)
	pip install -e ".[dev]"
	sieve serve
demo:            ## Load demo alerts and serve on http://localhost:8080 (no Wazuh, no AI needed)
	pip install -e ".[dev]"
	SIEVE_CONFIG=config/demo.yaml sieve demo
test:            ## Run the test suite with coverage on the core
	pytest -q --cov=sieve.pipeline --cov=sieve.llm --cov-fail-under=80
lint:            ## Lint
	ruff check sieve tests benchmark
bench:           ## PoisonedLogs benchmark with the mock (worst-case, obedient) model
	python benchmark/generate.py && python benchmark/run.py
up: setup        ## Start with Docker (Sieve only)
	docker compose up -d --build
up-ai: setup     ## Start with Docker and a local Ollama model server
	docker compose --profile ai up -d --build
	docker compose exec ollama ollama pull llama3.1:8b
down:            ## Stop containers
	docker compose --profile ai down
logs:            ## Follow logs
	docker compose logs -f sieve
token:           ## Print the ingest token for the Wazuh integration
	docker compose exec sieve sieve token
clean:           ## Delete local demo data
	rm -rf demo-data
