# Developer entry points. Requires: uv, Docker (with compose), GNU make, Node 22 for web-*.
# On Windows without make, run the commands on the right-hand side directly.

UV := uv --directory backend

.PHONY: setup dev down db test test-unit lint fmt typecheck migrate check demo \
	web-setup web-dev web-check api-types ai-eval bench

setup:  ## Install backend dependencies and create a local .env
	$(UV) sync --frozen
	@test -f backend/.env || cp .env.example backend/.env

dev:  ## Run postgres, migrations, api, worker and web
	docker compose up --build

down:
	docker compose down

db:  ## Start only PostgreSQL (for running tests or the API outside Docker)
	docker compose up -d --wait postgres

migrate: db
	$(UV) run python -m alembic upgrade head

demo: migrate  ## Load the advisory snapshot and queue the demo scan (a running worker completes it)
	$(UV) run python -m sieve.demo.seed

test: db  ## Unit + integration tests against a throwaway database (sieve_test)
	$(UV) run python -m pytest

test-unit:
	$(UV) run python -m pytest -m "not integration"

lint:
	$(UV) run ruff check src tests benchmarks
	$(UV) run ruff format --check src tests benchmarks

fmt:
	$(UV) run ruff check --fix src tests benchmarks
	$(UV) run ruff format src tests benchmarks

typecheck:
	$(UV) run python -m mypy src tests benchmarks

check: lint typecheck test  ## Everything CI runs for the backend

ai-eval:  ## Golden-dataset evaluation of the deterministic baseline, gated on the committed baseline
	$(UV) run python -m sieve.ai.evaluation --provider heuristic --out ../reports/ai-eval/heuristic \
		--baseline tests/ai/golden/baseline-heuristic.json

bench:  ## Scan and API benchmark (needs a running API on :8000 and a worker)
	$(UV) run python benchmarks/bench.py --label local --out ../reports/benchmarks/local

web-setup:
	cd web && npm ci

web-dev:  ## Next.js dev server on :3000, talking to the API on :8000
	cd web && npm run dev

api-types:  ## Regenerate web/openapi.json and the TypeScript API types from the backend
	$(UV) run python -X utf8 -c "import json; from sieve.api.app import create_app; print(json.dumps(create_app().openapi(), indent=2))" > web/openapi.json
	cd web && npm run api:types

web-check:  ## Everything CI runs for the frontend
	cd web && npm run typecheck && npm run lint && npm run build
