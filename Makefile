# go-signal Build System
# Production-grade Signal messaging server in Go

.DEFAULT_GOAL := build

# Project metadata
MODULE        := github.com/jeremyhahn/go-signal
SERVER_BINARY := signald
CLI_BINARY    := signal
BUILD_DIR     := build
BIN_DIR       := $(BUILD_DIR)/bin
COVER_DIR     := $(BUILD_DIR)/coverage
VERSION       := $(shell cat VERSION 2>/dev/null || echo "0.0.1-alpha")
GIT_COMMIT    := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE    := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS       := -X main.version=$(VERSION) -X main.gitCommit=$(GIT_COMMIT) -X main.buildDate=$(BUILD_DATE)

# Go tooling
GO            := go
GOTEST        := $(GO) test -race -count=1 -v
GOBUILD       := $(GO) build -ldflags "$(LDFLAGS)"
GOVET         := $(GO) vet
GOFMT         := gofmt
GOLINT        := golangci-lint
GOSEC         := gosec
GOVULNCHECK   := govulncheck

# gosec exclusions (documented):
#   G103: unsafe calls (test reflect/unsafe access for unexported fields)
#   G104: unhandled errors (false positive on hash.Write)
#   G115: integer overflow conversions (protocol-spec bounded IDs)
#   G304: file path via variable (config paths constructed internally)
GOSEC_EXCLUDE := G103,G104,G115,G304

# Coverage
COVER_MIN     := 90

# Docker
DOCKER_IMAGE  := go-signal-dev
DOCKER_TAG    := latest
COMPOSE_FILE  := .devcontainer/docker-compose.yml

# Package paths
PKG_ACCOUNTS       := ./pkg/accounts/...
PKG_AUTH            := ./pkg/auth/...
PKG_BACKUP          := ./pkg/backup/...
PKG_BADGES          := ./pkg/badges/...
PKG_CALLING         := ./pkg/calling/...
PKG_CAPTCHA         := ./pkg/captcha/...
PKG_CERTIFICATES    := ./pkg/certificates/...
PKG_CONFIG          := ./pkg/config/...
PKG_DEVICES         := ./pkg/devices/...
PKG_DIRECTORY       := ./pkg/directory/...
PKG_ERRORS          := ./pkg/errors/...
PKG_GROUPS          := ./pkg/groups/...
PKG_KEYS            := ./pkg/keys/...
PKG_KEYTRANSPARENCY := ./pkg/keytransparency/...
PKG_LIMITS          := ./pkg/limits/...
PKG_MESSAGES        := ./pkg/messages/...
PKG_METRICS         := ./pkg/metrics/...
PKG_PROFILES        := ./pkg/profiles/...
PKG_PUSH            := ./pkg/push/...
PKG_REGISTRATION    := ./pkg/registration/...
PKG_SECURESTORAGE   := ./pkg/securestorage/...
PKG_SVR             := ./pkg/securevaluerecovery/...
PKG_SERVICE         := ./pkg/service/...
PKG_SPAM            := ./pkg/spam/...
PKG_STICKERS        := ./pkg/stickers/...
PKG_STORE           := ./pkg/store/...
PKG_STORAGE         := ./pkg/storage/...
PKG_SUBSCRIPTIONS   := ./pkg/subscriptions/...
PKG_USERNAMES       := ./pkg/usernames/...
PKG_WEBSOCKET       := ./pkg/websocket/...
PKG_REST            := ./pkg/api/rest/...
PKG_GRPC            := ./pkg/api/grpc/...
PKG_API_WEBSOCKET   := ./pkg/api/websocket/...
PKG_VERIFICATION    := ./pkg/verification/...
PKG_FIDO2           := ./pkg/fido2/...
PKG_SECRETS         := ./pkg/config/secrets/...
PKG_CMD             := ./cmd/signald/...

# ==============================================================================
# Build
# ==============================================================================

# Feature flags (enabled by default, set to 0 to disable)
WITH_FIDO2   ?= 1
WITH_SMTP    ?= 0
WITH_DESKTOP ?= 1
WITH_FTS     ?= 1

# Assemble build tags from feature flags
BUILD_TAGS :=
ifeq ($(WITH_FIDO2),1)
  BUILD_TAGS += fido2
endif
ifeq ($(WITH_SMTP),1)
  BUILD_TAGS += smtp
endif
ifeq ($(WITH_DESKTOP),1)
  BUILD_TAGS += desktop codec_json
endif
ifeq ($(WITH_FTS),1)
  BUILD_TAGS += qrdb_fts
endif
BUILD_TAGS_FLAG := $(if $(strip $(BUILD_TAGS)),-tags "$(strip $(BUILD_TAGS))")

.PHONY: build build-server build-cli build-frontend dev-web proto

build: build-server build-cli

# build-frontend compiles the React/Vite SPA and copies the output into the
# internal/frontend/dist/ directory so that the Go embed directive in
# internal/frontend/frontend.go can pick it up at compile time.
build-frontend:
	@echo "==> Building frontend..."
	cd frontend && npm install --prefer-offline
	cd frontend && npm run build
	@echo "==> Copying frontend build output to internal/frontend/dist/..."
	@rm -rf internal/frontend/dist
	@cp -r $(BUILD_DIR)/frontend internal/frontend/dist
	@echo "==> Frontend build complete."

# build-server compiles the signald binary. The frontend must be built first
# when the web UI is desired; use build-all for a combined build.
build-server:
	@echo "==> Building server (tags: $(or $(strip $(BUILD_TAGS)),none))..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(BUILD_TAGS_FLAG) -o $(BIN_DIR)/$(SERVER_BINARY) ./cmd/signald/

# build-all builds the frontend then the server binary so that the web UI is
# embedded in the resulting binary.
.PHONY: build-all
build-all: build-frontend build-server build-cli

# dev-web starts both the frontend Vite dev server (with HMR) and the signald
# backend concurrently. Kill both processes with Ctrl-C.
dev-web:
	@echo "==> Starting frontend dev server and signald backend..."
	@trap 'kill 0' INT; \
	(cd frontend && npm run dev) & \
	$(GO) run ./cmd/signald/ start & \
	wait

build-cli:
	@echo "==> Building CLI (tags: $(or $(strip $(BUILD_TAGS)),none))..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(BUILD_TAGS_FLAG) -o $(BIN_DIR)/$(CLI_BINARY) ./cmd/signal/

# Desktop GUI explicit build tags (for build-desktop target)
BUILD_TAGS_DESKTOP := fido2,desktop,codec_json
ifeq ($(WITH_FTS),1)
BUILD_TAGS_DESKTOP := $(BUILD_TAGS_DESKTOP),qrdb_fts
endif

build-desktop: ## Build the Wails desktop application
	@echo "==> Building desktop client..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -tags $(BUILD_TAGS_DESKTOP) -o $(BIN_DIR)/$(CLI_BINARY)-desktop ./cmd/signal/

dev-desktop: ## Run Wails dev mode with hot reload
	@echo "==> Starting desktop dev mode..."
	cd frontend && npm install
	wails dev -tags $(BUILD_TAGS_DESKTOP)

test-desktop: ## Run desktop package unit tests
	@echo "==> Testing desktop packages..."
	$(GOTEST) -tags $(BUILD_TAGS_DESKTOP) ./pkg/desktop/...

coverage-desktop: ## Coverage report for desktop packages
	@echo "==> Desktop coverage..."
	@mkdir -p $(COVER_DIR)
	$(GO) test -tags $(BUILD_TAGS_DESKTOP) -coverprofile=$(COVER_DIR)/desktop.out ./pkg/desktop/...
	$(GO) tool cover -func=$(COVER_DIR)/desktop.out

proto:
	@echo "==> Generating protobuf code..."
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		pkg/api/grpc/proto/*.proto

# ==============================================================================
# Testing
# ==============================================================================

.PHONY: test integration-test

test:
	@echo "==> Running unit tests (tags: $(or $(strip $(BUILD_TAGS)),none))..."
	@mkdir -p $(COVER_DIR)
	$(GOTEST) $(BUILD_TAGS_FLAG) -coverprofile=$(COVER_DIR)/coverage.out \
		-covermode=atomic \
		./pkg/... ./cmd/... 2>&1 | tee $(BUILD_DIR)/test.log
	@echo "==> Tests complete."

# integration-test runs E2E integration tests inside the devcontainer.
# When SIGNAL_SERVER_URL is set (inside the container), run go test directly.
# Otherwise, bring up docker-compose and run tests in the integration container.
integration-test:
ifdef SIGNAL_SERVER_URL
	@echo "==> Running integration tests against $(SIGNAL_SERVER_URL)..."
	@mkdir -p $(COVER_DIR)
	$(GOTEST) -tags integration -timeout 120m \
		-coverprofile=$(COVER_DIR)/integration-coverage.out \
		-covermode=atomic \
		./test/integration/... 2>&1 | tee $(BUILD_DIR)/integration-test.log
	@echo "==> Integration tests complete."
else
	@echo "==> Starting devcontainer infrastructure..."
	@mkdir -p $(BUILD_DIR)
	docker compose -f .devcontainer/docker-compose.yml build signal-server signal-cli integration
	docker compose -f .devcontainer/docker-compose.yml run --rm integration 2>&1 | tee $(BUILD_DIR)/integration-test.log
	@echo "==> Integration tests complete."
endif

# integration-test-fido2 runs FIDO2/WebAuthn integration tests using an
# in-process server.
.PHONY: integration-test-fido2
integration-test-fido2:
	@echo "==> Running FIDO2 integration tests..."
	@mkdir -p $(BUILD_DIR)
	$(GOTEST) -tags "integration,fido2" -timeout 120s \
		./test/integration/... 2>&1 | tee $(BUILD_DIR)/integration-test-fido2.log
	@echo "==> FIDO2 integration tests complete."

# integration-test-cli runs table-driven CLI parity tests against both
# signal-cli (Java) and our signal (Go) binary.
.PHONY: integration-test-cli
integration-test-cli: build
	@echo "==> Running CLI parity integration tests..."
	@mkdir -p $(BUILD_DIR)
	SIGNAL_GO_BIN=$(CURDIR)/$(BIN_DIR)/signal \
	$(GOTEST) -tags integration -timeout 120s \
		./test/integration/cli/... 2>&1 | tee $(BUILD_DIR)/integration-test-cli.log
	@echo "==> CLI parity integration tests complete."

# Per-package unit tests
.PHONY: test-accounts test-auth test-backup test-badges test-calling test-captcha
.PHONY: test-certificates test-config test-devices test-directory test-errors
.PHONY: test-groups test-keys test-keytransparency test-limits test-messages
.PHONY: test-metrics test-profiles test-push test-registration test-securestorage
.PHONY: test-svr test-service test-spam test-stickers test-storage
.PHONY: test-store test-subscriptions test-usernames test-websocket test-rest test-grpc
.PHONY: test-api-websocket test-cmd
.PHONY: test-verification test-fido2 test-smtp test-secrets

test-accounts:
	$(GOTEST) $(PKG_ACCOUNTS)
test-auth:
	$(GOTEST) $(PKG_AUTH)
test-backup:
	$(GOTEST) $(PKG_BACKUP)
test-badges:
	$(GOTEST) $(PKG_BADGES)
test-calling:
	$(GOTEST) $(PKG_CALLING)
test-captcha:
	$(GOTEST) $(PKG_CAPTCHA)
test-certificates:
	$(GOTEST) $(PKG_CERTIFICATES)
test-config:
	$(GOTEST) $(PKG_CONFIG)
test-devices:
	$(GOTEST) $(PKG_DEVICES)
test-directory:
	$(GOTEST) $(PKG_DIRECTORY)
test-errors:
	$(GOTEST) $(PKG_ERRORS)
test-groups:
	$(GOTEST) $(PKG_GROUPS)
test-keys:
	$(GOTEST) $(PKG_KEYS)
test-keytransparency:
	$(GOTEST) $(PKG_KEYTRANSPARENCY)
test-limits:
	$(GOTEST) $(PKG_LIMITS)
test-messages:
	$(GOTEST) $(PKG_MESSAGES)
test-metrics:
	$(GOTEST) $(PKG_METRICS)
test-profiles:
	$(GOTEST) $(PKG_PROFILES)
test-push:
	$(GOTEST) $(PKG_PUSH)
test-registration:
	$(GOTEST) $(PKG_REGISTRATION)
test-securestorage:
	$(GOTEST) $(PKG_SECURESTORAGE)
test-svr:
	$(GOTEST) $(PKG_SVR)
test-service:
	$(GOTEST) $(PKG_SERVICE)
test-spam:
	$(GOTEST) $(PKG_SPAM)
test-stickers:
	$(GOTEST) $(PKG_STICKERS)
test-store:
	$(GOTEST) $(PKG_STORE)
test-storage:
	$(GOTEST) $(PKG_STORAGE)
test-subscriptions:
	$(GOTEST) $(PKG_SUBSCRIPTIONS)
test-usernames:
	$(GOTEST) $(PKG_USERNAMES)
test-websocket:
	$(GOTEST) $(PKG_WEBSOCKET)
test-rest:
	$(GOTEST) $(PKG_REST)
test-grpc:
	$(GOTEST) $(PKG_GRPC)
test-api-websocket:
	$(GOTEST) $(PKG_API_WEBSOCKET)
test-cmd:
	$(GOTEST) $(PKG_CMD)
test-verification:
	$(GOTEST) $(PKG_VERIFICATION)
test-fido2:
	$(GOTEST) $(BUILD_TAGS_FLAG) $(PKG_FIDO2)
test-smtp:
	$(GOTEST) -tags smtp ./pkg/verification/smtp/...
test-secrets:
	$(GOTEST) $(PKG_SECRETS)

# ==============================================================================
# Coverage
# ==============================================================================

# Packages excluded from coverage reporting (generated code, test harness, CLI entry points)
COVERAGE_EXCLUDE_PATTERN := /test/|/cmd/signalctl|/cmd/signald|/wsproto

# All testable packages (excluding test directories)
ALL_PACKAGES := $(shell go list ./... 2>/dev/null | grep -vE '$(COVERAGE_EXCLUDE_PATTERN)')

# Testable package short names for per-package targets
TESTABLE_PACKAGES := accounts api/rest api/websocket calling captcha certificates \
	config config/secrets devices directory errors keys keytransparency messages \
	profiles securestorage securevaluerecovery stickers store storage/memory \
	usernames verification websocket

.PHONY: coverage

coverage:
	@echo "==> Generating coverage report..."
	@mkdir -p $(COVER_DIR)
	@echo "mode: atomic" > $(COVER_DIR)/coverage.out
	@PKGS=$$(go list $(BUILD_TAGS_FLAG) ./... 2>/dev/null | grep -vE '$(COVERAGE_EXCLUDE_PATTERN)'); \
	for pkg in $$PKGS; do \
		$(GO) test -race -count=1 $(BUILD_TAGS_FLAG) -coverprofile=$(COVER_DIR)/pkg.out -covermode=atomic "$$pkg" 2>/dev/null; \
		if [ -f $(COVER_DIR)/pkg.out ]; then \
			tail -n +2 $(COVER_DIR)/pkg.out >> $(COVER_DIR)/coverage.out; \
			rm -f $(COVER_DIR)/pkg.out; \
		fi; \
	done
	@go tool cover -func=$(COVER_DIR)/coverage.out
	@echo ""
	@echo "HTML report: $(COVER_DIR)/coverage.html"
	@go tool cover -html=$(COVER_DIR)/coverage.out -o $(COVER_DIR)/coverage.html
	@echo ""
	@TOTAL=$$(go tool cover -func=$(COVER_DIR)/coverage.out | grep '^total:' | awk '{print $$NF}'); \
	echo "=== TOTAL CODE COVERAGE: $$TOTAL ==="; \
	PCT=$$(echo "$$TOTAL" | tr -d '%'); \
	if [ $$(echo "$$PCT < $(COVER_MIN)" | bc -l 2>/dev/null || echo 0) -eq 1 ]; then \
		echo "FAIL: Coverage $$TOTAL is below minimum $(COVER_MIN)%"; \
		exit 1; \
	else \
		echo "PASS: Coverage $$TOTAL meets minimum $(COVER_MIN)%"; \
	fi

# Per-package coverage targets: make coverage-accounts, make coverage-keys, etc.
$(addprefix coverage-,$(TESTABLE_PACKAGES)):
	@mkdir -p $(COVER_DIR)
	@$(GO) test -race -count=1 -coverprofile=$(COVER_DIR)/$(subst /,_,$(subst coverage-,,$@)).out \
		-covermode=atomic ./pkg/$(subst coverage-,,$@)/...
	@go tool cover -func=$(COVER_DIR)/$(subst /,_,$(subst coverage-,,$@)).out
	@echo ""
	@TOTAL=$$(go tool cover -func=$(COVER_DIR)/$(subst /,_,$(subst coverage-,,$@)).out | grep '^total:' | awk '{print $$NF}'); \
	echo "=== $(subst coverage-,,$@) COVERAGE: $$TOTAL ==="; \
	PCT=$$(echo "$$TOTAL" | tr -d '%'); \
	if [ $$(echo "$$PCT < $(COVER_MIN)" | bc -l 2>/dev/null || echo 0) -eq 1 ]; then \
		echo "FAIL: Coverage $$TOTAL is below minimum $(COVER_MIN)%"; \
		exit 1; \
	else \
		echo "PASS: Coverage $$TOTAL meets minimum $(COVER_MIN)%"; \
	fi

# Build-tagged coverage targets
.PHONY: coverage-fido2 coverage-smtp

coverage-fido2:
	@mkdir -p $(COVER_DIR)
	@$(GO) test -race -count=1 $(BUILD_TAGS_FLAG) -coverprofile=$(COVER_DIR)/fido2.out \
		-covermode=atomic ./pkg/fido2/...
	@go tool cover -func=$(COVER_DIR)/fido2.out
	@echo ""
	@TOTAL=$$(go tool cover -func=$(COVER_DIR)/fido2.out | grep '^total:' | awk '{print $$NF}'); \
	echo "=== fido2 COVERAGE: $$TOTAL ==="

coverage-smtp:
	@mkdir -p $(COVER_DIR)
	@$(GO) test -race -count=1 -tags smtp -coverprofile=$(COVER_DIR)/smtp.out \
		-covermode=atomic ./pkg/verification/smtp/...
	@go tool cover -func=$(COVER_DIR)/smtp.out
	@echo ""
	@TOTAL=$$(go tool cover -func=$(COVER_DIR)/smtp.out | grep '^total:' | awk '{print $$NF}'); \
	echo "=== smtp COVERAGE: $$TOTAL ==="

# ==============================================================================
# CI / Quality
# ==============================================================================

.PHONY: ci fmt vet lint gosec vuln

ci: fmt vet lint gosec vuln build test
	@echo "==> CI pipeline complete."

fmt:
	@echo "==> Checking formatting..."
	@test -z "$$($(GOFMT) -l .)" || (echo "Files need formatting:"; $(GOFMT) -l .; exit 1)

vet:
	@echo "==> Running go vet..."
	$(GOVET) ./...

lint:
	@echo "==> Running linter..."
	$(GOLINT) run --timeout 5m ./...

gosec:
	@echo "==> Running security scanner..."
	$(GOSEC) -exclude=$(GOSEC_EXCLUDE) ./...

vuln:
	@echo "==> Running vulnerability check..."
	$(GOVULNCHECK) ./...

# ==============================================================================
# Docker
# ==============================================================================

.PHONY: docker-build docker-run

docker-build:
	@echo "==> Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

docker-run:
	@echo "==> Running Docker container..."
	docker run --rm -p 8081:8081 -p 8443:8443 $(DOCKER_IMAGE):$(DOCKER_TAG)

# ==============================================================================
# Integration Testing with signal-cli
# ==============================================================================

.PHONY: docker-build-signal-cli docker-compose-up docker-compose-down

docker-build-signal-cli:
	@echo "==> Building signal-cli Docker image..."
	docker build -t signal-cli-custom:latest ./test/signal-cli/

docker-compose-up:
	@echo "==> Starting test infrastructure..."
	docker compose -f .devcontainer/docker-compose.yml up -d --build

docker-compose-down:
	@echo "==> Stopping test infrastructure..."
	docker compose -f .devcontainer/docker-compose.yml down -v

# ==============================================================================
# Development
# ==============================================================================

.PHONY: dev deps clean

dev:
	@echo "==> Starting development server..."
	$(GO) run ./cmd/signald/ start

deps:
	@echo "==> Downloading dependencies..."
	$(GO) mod download
	$(GO) mod tidy

clean:
	@echo "==> Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)

# ==============================================================================
# Frontend E2E Tests
# ==============================================================================

.PHONY: test-e2e

test-e2e: ## Run Playwright E2E tests against the Vite dev server
	@echo "==> Running Playwright E2E tests..."
	@mkdir -p $(BUILD_DIR)
	cd frontend && npx playwright test 2>&1 | tee ../$(BUILD_DIR)/e2e-test.log
	@echo "==> E2E tests complete."
