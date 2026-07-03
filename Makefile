# fr-security-review — build / install / validation helpers.
# `make` or `make help` lists targets. Codex/OpenCode bundles land in dist/ (gitignored).

.DEFAULT_GOAL := help
.PHONY: help build-codex build-opencode install-codex install-opencode check test-build test-engine

help: ## List available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[1m%-18s\033[0m %s\n", $$1, $$2}'

build-codex: ## Build the Codex bundle into dist/codex
	python3 build/build.py --harness=codex --mode=write --out=dist/codex

build-opencode: ## Build the OpenCode bundle into dist/opencode
	python3 build/build.py --harness=opencode --mode=write --out=dist/opencode

install-codex: ## Build + register + install the Codex plugin (self-hosted marketplace)
	./scripts/install-codex.sh

install-opencode: ## Build + install OpenCode commands/agents (OPENCODE_SCOPE=global|project)
	./scripts/install-opencode.sh

check: ## Full local validation gate (3-harness anti-drift + build + engine + plugin validate)
	python3 build/build.py --harness=claude   --mode=check
	python3 build/build.py --harness=opencode --mode=check
	python3 build/build.py --harness=codex    --mode=check
	python3 -m unittest discover -s build/tests
	python3 -m unittest discover -s security-review/bin/tests
	claude plugin validate .

test-build: ## Run the build-tooling test suite (fast)
	python3 -m unittest discover -s build/tests

test-engine: ## Run the engine test suite (~1219 tests, ~50s)
	python3 -m unittest discover -s security-review/bin/tests
