# Valkyrie — chooses who passes.
SHELL := /bin/bash
ROOT  := $(shell pwd)
export PYTHONPATH := $(ROOT)/sdk/python
export OPA_BIN ?= opa

.PHONY: help deps registry policy-test gateway gateway-test py-test test up down demo smoke fmt lint clean

help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

deps: ## Install Python deps (Go and OPA are prerequisites)
	pip install -q -r requirements.txt

registry: ## Validate manifests and build registry/registry.json
	python3 scripts/build_registry.py

policy-test: ## opa fmt/check/test
	$(OPA_BIN) fmt --fail -l policies > /dev/null || (echo "run: opa fmt -w policies"; exit 1)
	$(OPA_BIN) check --strict --ignore=tests policies
	$(OPA_BIN) test policies -v --coverage --format=json | python3 -c "import sys,json; c=json.load(sys.stdin)['coverage']; print(f'rego coverage {c:.1f}%'); sys.exit(c < 90)"
	OPA_BIN=$(OPA_BIN) python3 scripts/policy_regression.py

gateway: ## Build the gateway, registryd and valkyriectl into bin/
	cd gateway && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=0.2.0" -o ../bin/valkyrie ./cmd/valkyrie
	cd controlplane && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../bin/registryd ./cmd/registryd
	cd controlplane && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../bin/valkyriectl ./cmd/valkyriectl

gateway-test: ## go vet + go test -race for the gateway and the control plane
	cd gateway && go vet ./... && go test -race -count=1 ./...
	cd controlplane && go vet ./... && go test -race -count=1 ./...

py-test: ## Python unit tests
	python3 -m pytest -q sdk/python/tests

test: registry policy-test gateway-test py-test ## Everything that runs without a live stack

up: registry gateway ## Start registryd + OPA + servers + gateway locally
	mkdir -p .dev && ./scripts/dev_up.sh

down: ## Stop the local stack
	./scripts/dev_down.sh

demo: up ## Run the pizza scenario end to end
	cd agents/pizza && python3 run.py; cd $(ROOT) && $(MAKE) -s down

smoke: up ## Exercise the /mcp face with the official MCP client
	python3 scripts/smoke_mcp.py; $(MAKE) -s down

reference: up ## Onboard a third-party MCP server and a REST API through the control plane, then call them
	./scripts/reference.sh; $(MAKE) -s down

e2e: ## demo + smoke + reference against one running stack
	$(MAKE) -s up && (cd agents/pizza && python3 run.py) && python3 scripts/smoke_mcp.py && ./scripts/reference.sh; $(MAKE) -s down

fmt: ## Format Go and Rego
	cd gateway && gofmt -w . ; $(OPA_BIN) fmt -w policies

clean:
	rm -rf bin .dev registry/registry.json policies/tool_tiers.json reference/node_modules
