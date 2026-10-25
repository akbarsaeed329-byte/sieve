.PHONY: help setup dev demo test lint up up-ai down logs token clean
help:            ## Show targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'
setup:           ## Create config/sieve.yaml and .env from the examples (keeps existing files)
	@test -f config/sieve.yaml || cp config/sieve.example.yaml config/sieve.yaml
	@test -f .env || cp .env.example .env
	@echo "Edit config/sieve.yaml and .env, then run 'make up' or 'make dev'."
dev: setup       ## Run locally with Python (no Docker)
	pip install -e ".[dev]"
	sieve serve
demo:            ## Run locally with built-in demo alerts, no Wazuh needed
	pip install -e ".[dev]"
	SIEVE_CONFIG=config/demo.yaml sieve demo
test:            ## Run the test suite
	pytest -q
lint:            ## Lint
	ruff check sieve tests
up: setup        ## Start with Docker
	docker compose up -d --build
up-ai: setup     ## Start with Docker and a local Ollama model server
	docker compose --profile ai up -d --build
	docker compose exec ollama ollama pull llama3.1:8b
down:            ## Stop containers
	docker compose down
logs:            ## Follow logs
	docker compose logs -f sieve
token:           ## Print the ingest token for the Wazuh integration
	docker compose exec sieve sieve token
clean:           ## Delete local demo data
	rm -rf demo-data
