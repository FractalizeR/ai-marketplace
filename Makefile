# fr-security-review — build / install / validation helpers.
# `make` or `make help` lists targets. Codex/OpenCode bundles land in dist/ (gitignored).

.DEFAULT_GOAL := help
.PHONY: help build-codex build-opencode install-codex install-opencode install-launchers check test-build test-engine

REPO := $(CURDIR)
BINDIR ?= $(HOME)/.local/bin

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

install-launchers: ## Install the `frsr` launcher into BINDIR (default ~/.local/bin)
	@mkdir -p "$(BINDIR)"
	@python3 -c 'import sys,pathlib; src,dst,repo=sys.argv[1:4]; pathlib.Path(dst).write_text(pathlib.Path(src).read_text().replace("@@REPO@@", repo))' scripts/frsr "$(BINDIR)/frsr" '$(REPO)'
	@chmod +x "$(BINDIR)/frsr"
	@echo "Installed $(BINDIR)/frsr (repo baked as $(REPO))"
	@case ":$$PATH:" in *":$(BINDIR):"*) : ;; \
		*) echo "WARNING: $(BINDIR) is not on PATH — add it to your shell rc" ;; esac
	@echo "Try: frsr project --harness opencode --dry-run"

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
