# C³ - Makefile. Everything runs in Docker. Nothing touches your host Python.
#
# Targets:
#   make build     - build the ccc image
#   make audit     - verify pinned dep hashes match PyPI before trusting lockfile
#   make test      - run the unittest suite in a container
#   make run       - one poll cycle (uses ./config/config.yaml)
#   make dry-run   - poll + print alerts, send nothing
#   make webhook   - send a fake card to verify Google Chat webhook
#   make shell     - interactive shell inside the container (debugging)
#   make state     - dump the ccc-state volume contents
#   make clean     - remove image + state volume (DESTRUCTIVE)
#   make logs      - tail audit.jsonl

.PHONY: build audit test run dry-run webhook shell state clean logs help

COMPOSE := docker compose

help:
	@awk 'BEGIN{FS=":.*##"} /^[a-zA-Z_-]+:.*##/{printf "  \033[36m%-12s\033[0m %s\n",$$1,$$2}' $(MAKEFILE_LIST)

build: ## Build the ccc:local image
	$(COMPOSE) build

audit: ## Verify SHA256 of every pinned dep against PyPI (run before trusting lockfile)
	$(COMPOSE) run --rm audit

test: build ## Run the dedup test suite inside container
	$(COMPOSE) run --rm test

validate: build ## Validate config + resolve product CPEs (no NVD poll)
	$(COMPOSE) run --rm ccc validate

run: build ## One poll cycle. Reads ./config/config.yaml
	$(COMPOSE) run --rm ccc run

dry-run: build ## One poll cycle but print alerts instead of sending
	$(COMPOSE) run --rm ccc run --dry-run

webhook: build ## Send a test card to verify Google Chat webhook
	$(COMPOSE) run --rm ccc test-webhook

shell: build ## Interactive shell (sh) for debugging
	$(COMPOSE) run --rm --entrypoint /bin/sh ccc

state: ## Show state volume contents
	$(COMPOSE) run --rm --entrypoint /bin/sh ccc -c 'ls -la /state && echo --- && cat /state/last_run.txt 2>/dev/null; echo --- && cat /state/recent.json 2>/dev/null'

logs: ## Tail the alert audit log
	$(COMPOSE) run --rm --entrypoint /bin/sh ccc -c 'tail -f /state/audit.jsonl 2>/dev/null || echo "no audit log yet"'

clean: ## Remove image + state volume
	-$(COMPOSE) down -v
	-docker rmi ccc:local
