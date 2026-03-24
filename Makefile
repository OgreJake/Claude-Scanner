.PHONY: all build build-agent build-netscanner build-all-agents \
        install dev-install migrate db-upgrade db-downgrade \
        run run-dev run-worker \
        web-install web-dev web-build \
        test test-python test-go lint \
        docker-up docker-down docker-logs \
        clean help

BINARY_DIR     := bin
AGENT_SRC      := ./cmd/agent
NETSCANNER_SRC := ./cmd/netscanner
PYTHON_SRC     := server cli

# OS/Arch targets for cross-compiled agent binaries
AGENT_TARGETS := \
	linux/amd64 linux/arm64 \
	windows/amd64 windows/arm64 \
	darwin/amd64 darwin/arm64 \
	freebsd/amd64

##@ Build

build: build-agent build-netscanner ## Build all Go binaries for current platform

build-agent: ## Build scanner agent for current platform
	@echo "Building scanner agent..."
	@mkdir -p $(BINARY_DIR)
	go build -ldflags="-s -w" -o $(BINARY_DIR)/claude-agent $(AGENT_SRC)

build-netscanner: ## Build network scanner for current platform
	@echo "Building network scanner..."
	@mkdir -p $(BINARY_DIR)
	go build -ldflags="-s -w" -o $(BINARY_DIR)/claude-netscanner $(NETSCANNER_SRC)

build-all-agents: ## Cross-compile agent binaries for all target platforms
	@echo "Cross-compiling agent for all platforms..."
	@mkdir -p $(BINARY_DIR)/agents
	@$(foreach TARGET,$(AGENT_TARGETS), \
		$(eval OS=$(word 1,$(subst /, ,$(TARGET)))) \
		$(eval ARCH=$(word 2,$(subst /, ,$(TARGET)))) \
		$(eval EXT=$(if $(filter windows,$(OS)),.exe,)) \
		echo "  Building $(OS)/$(ARCH)..."; \
		GOOS=$(OS) GOARCH=$(ARCH) go build -ldflags="-s -w" \
			-o $(BINARY_DIR)/agents/claude-agent-$(OS)-$(ARCH)$(EXT) $(AGENT_SRC); \
	)
	@echo "Agent binaries in $(BINARY_DIR)/agents/"

##@ Python / Server

install: ## Install Python dependencies
	pip install -e .

dev-install: ## Install Python dependencies including dev tools
	pip install -e ".[dev]"

run: ## Run the API server (production)
	uvicorn server.main:app --host 0.0.0.0 --port 8000

run-dev: ## Run the API server with hot-reload
	uvicorn server.main:app --host 0.0.0.0 --port 8000 --reload

run-worker: ## Run Celery worker for background scan tasks
	celery -A server.tasks.celery_app worker --loglevel=info --concurrency=8

##@ Database

migrate: ## Create a new Alembic migration (MESSAGE required: make migrate MESSAGE="add foo")
	alembic revision --autogenerate -m "$(MESSAGE)"

db-upgrade: ## Apply all pending migrations
	alembic upgrade head

db-downgrade: ## Revert last migration
	alembic downgrade -1

##@ Web

web-install: ## Install web dashboard dependencies
	cd web && npm install

web-dev: ## Run web dashboard dev server
	cd web && npm run dev

web-build: ## Build web dashboard for production
	cd web && npm run build

##@ Testing

test: test-python test-go ## Run all tests

test-python: ## Run Python tests
	pytest tests/ -v --tb=short

test-go: ## Run Go tests
	go test ./... -v

lint: ## Run linters
	ruff check $(PYTHON_SRC)
	ruff format --check $(PYTHON_SRC)
	go vet ./...

##@ Docker

docker-up: ## Build and start all services via Docker Compose
	docker compose -f deploy/docker-compose.yml up -d --build

docker-down: ## Stop all services
	docker compose -f deploy/docker-compose.yml down

docker-logs: ## Tail logs from all services
	docker compose -f deploy/docker-compose.yml logs -f

docker-build: ## Rebuild Docker images
	docker compose -f deploy/docker-compose.yml build

##@ Utilities

clean: ## Remove build artifacts
	rm -rf $(BINARY_DIR)
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete

help: ## Show this help message
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
		/^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)
