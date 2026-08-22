# go-signal Build System
# Production-grade Signal messaging server in Go

.DEFAULT_GOAL := build

# ==============================================================================
# Help
# ==============================================================================

.PHONY: help all

help: ## Display available targets
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make <target>\n\nTargets:\n"} /^[a-zA-Z_0-9\/-]+:.*?##/ { printf "  %-24s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

all: clean deps lint test build ## Run clean, deps, lint, test and build
	@echo "==> All targets completed successfully."

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

# The scanners are pinned for the same reason golangci-lint is: unpinned, they
# decide whether the security gate is red based on what upstream released that
# morning. A new rule turns the gate red on a diff that touched nothing, and —
# worse, because nothing announces it — a rule that stops firing silently
# narrows the gate.
#
# Baseline: both versions verified green over the FULL build-tagged tree
# (446 files, 0 gosec issues; govulncheck 0 affecting vulnerabilities) as of
# 2026-08-22. Bumping either is a normal reviewed change with a visible diff,
# which is the point — it stops being something that happens to everyone at
# once.
#
# Pinning the govulncheck BINARY does not freeze its findings, and must not:
# the vulnerability database is fetched at run time, so a newly published CVE
# against a dependency we do call still turns this gate red. That variability
# is the gate working.
#
# There is deliberately no local version check for gosec. A gosec built by
# `go install ...@v2.28.0` reports `Version: dev` — the real version is
# injected by ldflags in the release build only — so the binary cannot be asked
# what it is, and a check would warn on every correctly-pinned machine until
# people learned to ignore it. CI installs the pin explicitly, which is where
# determinism actually matters.
GOSEC_VERSION       := v2.28.0
GOVULNCHECK_VERSION := v1.7.0

# gosec exclusions (documented):
#   G103: unsafe calls (test reflect/unsafe access for unexported fields)
#   G104: unhandled errors (false positive on hash.Write)
#   G115: integer overflow conversions (protocol-spec bounded IDs)
#   G304: file path via variable (config paths constructed internally)
#   G118: cancel-func ownership transferred to caller (Go idiom: helpers
#         that build a (ctx, cancel) pair return both; the caller defers
#         cancel — gosec doesn't track interprocedural ownership)
GOSEC_EXCLUDE := G103,G104,G115,G304,G118

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

# gosec wants a COMMA-separated tag list, unlike the go tool and
# golangci-lint. A space-separated one is not rejected — it is read as a single
# tag nobody declared, so it matches nothing and the run looks normal.
# Measured: the space form scanned the same 414 files as an untagged run while
# the comma form scanned 445.
comma      := ,
space      := $(subst ,, )
GOSEC_TAGS := $(subst $(space),$(comma),$(strip $(BUILD_TAGS)))

# The one place the default tag set is defined. CI jobs that cannot call a make
# target directly (the FIPS job builds and tests ./... under GOFIPS140, which no
# build target covers) read the set from here instead of restating it, so the
# flags cannot drift out of sync with the feature switches above. A job that
# omitted them built without codec_json and failed on every dao-backed package.
print-build-tags: ## Print the default build tag set (for CI and tooling)
	@echo '$(strip $(BUILD_TAGS))'

# Same contract as print-build-tags: CI installs the scanners itself and reads
# the versions from here, so the pin cannot drift out of sync with the Makefile
# that documents it.
print-gosec-version: ## Print the pinned gosec version (for CI)
	@echo '$(GOSEC_VERSION)'

print-govulncheck-version: ## Print the pinned govulncheck version (for CI)
	@echo '$(GOVULNCHECK_VERSION)'

.PHONY: print-build-tags print-gosec-version print-govulncheck-version
.PHONY: build build-server build-cli build-frontend dev-web proto proto-tools
.PHONY: build-cdsi build-svr2 build-key-transparency build-registration-service build-storage-service build-services

build: build-server build-cli ## Build server and CLI binaries

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
build-all: build-frontend build-server build-cli ## Build frontend, server and CLI

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

# ==============================================================================
# Auxiliary service binaries
# ==============================================================================

build-cdsi:
	@echo "==> Building cdsi (tags: $(or $(strip $(BUILD_TAGS)),none))..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(BUILD_TAGS_FLAG) -o $(BIN_DIR)/cdsi ./cmd/cdsi/

build-svr2:
	@echo "==> Building svr2 (tags: $(or $(strip $(BUILD_TAGS)),none))..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(BUILD_TAGS_FLAG) -o $(BIN_DIR)/svr2 ./cmd/svr2/

build-key-transparency:
	@echo "==> Building key-transparency (tags: $(or $(strip $(BUILD_TAGS)),none))..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(BUILD_TAGS_FLAG) -o $(BIN_DIR)/key-transparency ./cmd/key-transparency/

build-registration-service:
	@echo "==> Building registration-service (tags: $(or $(strip $(BUILD_TAGS)),none))..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(BUILD_TAGS_FLAG) -o $(BIN_DIR)/registration-service ./cmd/registration-service/

build-storage-service:
	@echo "==> Building storage-service (tags: $(or $(strip $(BUILD_TAGS)),none))..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(BUILD_TAGS_FLAG) -o $(BIN_DIR)/storage-service ./cmd/storage-service/

# build-services builds all five auxiliary service binaries.
build-services: build-cdsi build-svr2 build-key-transparency build-registration-service build-storage-service ## Build all auxiliary service binaries
	@echo "==> All auxiliary service binaries built."

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

# protoc and its plugins are pinned because an unpinned generator does not
# fail — it rewrites EVERY generated file. protoc stamps its own version into
# each header, so a mismatched local protoc turns `make proto` into a 34-file
# diff with the one real change buried in it. Measured on PR #29, where staging
# the package after a regeneration swept 39 unrelated files into a commit about
# something else, and the workaround was to invoke protoc for a single .proto
# by hand — which the Makefile should not require anyone to know.
#
# The two spellings of the protoc version are not a typo. `protoc --version`
# prints "libprotoc 25.1" while the code it generates stamps "v4.25.1":
# protobuf renumbered its releases after 3.20 and the generator kept the 4.x
# form. PROTOC_VERSION is the string the binary reports, because that is what
# the check below can compare.
PROTOC_VERSION             := 25.1
PROTOC_GEN_GO_VERSION      := v1.36.11
PROTOC_GEN_GO_GRPC_VERSION := 1.6.1

# proto-tools fails closed on a version mismatch rather than letting the
# generation proceed and rewrite the tree. Each check reports what it found, so
# the message is actionable without re-running anything by hand.
proto-tools: ## Verify the pinned protoc and plugin versions are installed
	@fail=0; \
	have=$$(protoc --version 2>/dev/null | awk '{print $$2}'); \
	if [ "$$have" != "$(PROTOC_VERSION)" ]; then \
		echo "FAIL: protoc $(PROTOC_VERSION) required, found $${have:-none}."; \
		echo "      https://github.com/protocolbuffers/protobuf/releases/tag/v$(PROTOC_VERSION)"; \
		fail=1; \
	fi; \
	have=$$(PATH=$(GOPATH_BIN):$$PATH protoc-gen-go --version 2>/dev/null | awk '{print $$2}'); \
	if [ "$$have" != "$(PROTOC_GEN_GO_VERSION)" ]; then \
		echo "FAIL: protoc-gen-go $(PROTOC_GEN_GO_VERSION) required, found $${have:-none}."; \
		echo "      go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)"; \
		fail=1; \
	fi; \
	have=$$(PATH=$(GOPATH_BIN):$$PATH protoc-gen-go-grpc --version 2>/dev/null | awk '{print $$2}'); \
	if [ "$$have" != "$(PROTOC_GEN_GO_GRPC_VERSION)" ]; then \
		echo "FAIL: protoc-gen-go-grpc $(PROTOC_GEN_GO_GRPC_VERSION) required, found $${have:-none}."; \
		echo "      go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v$(PROTOC_GEN_GO_GRPC_VERSION)"; \
		fail=1; \
	fi; \
	if [ $$fail -ne 0 ]; then \
		echo "Generating with an unpinned toolchain rewrites every file in pkg/api/grpc/genproto."; \
		exit 1; \
	fi; \
	echo "==> protoc $(PROTOC_VERSION), protoc-gen-go $(PROTOC_GEN_GO_VERSION), protoc-gen-go-grpc $(PROTOC_GEN_GO_GRPC_VERSION)"

proto: proto-tools
	@echo "==> Generating protobuf code..."
	@mkdir -p pkg/api/grpc/genproto
	@PATH=$(GOPATH_BIN):$$PATH protoc \
		--go_out=pkg/api/grpc/genproto \
		--go-grpc_out=pkg/api/grpc/genproto \
		-I pkg/api/grpc/proto \
		pkg/api/grpc/proto/org/signal/chat/*.proto \
		pkg/api/grpc/proto/RegistrationService.proto \
		pkg/api/grpc/proto/KeyTransparencyService.proto \
		pkg/api/grpc/proto/WebSocketConnectionEvent.proto \
		pkg/api/grpc/proto/CallQualitySurveyPubSub.proto \
		pkg/api/grpc/proto/DisconnectionRequests.proto \
		pkg/api/grpc/proto/cdsi.proto \
		pkg/api/grpc/proto/directory.proto \
		pkg/api/grpc/proto/TextSecure.proto
	@# protoc places output under the full go_package path; flatten it.
	@# Using cp + rm is idempotent across reruns (mv fails when target
	@# subdirectories already exist from a previous generation).
	@if [ -d pkg/api/grpc/genproto/github.com ]; then \
		cp -r pkg/api/grpc/genproto/github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/. pkg/api/grpc/genproto/; \
		rm -rf pkg/api/grpc/genproto/github.com; \
	fi
	@echo "==> Protobuf generation complete."

# GOPATH_BIN holds the Go install bin dir where protoc-gen-go lives.
GOPATH_BIN := $(shell go env GOPATH)/bin

# ==============================================================================
# Testing
# ==============================================================================

.PHONY: test integration-test

# ./sdk/... is in scope deliberately. It was omitted until 2026-08-14, which
# meant the client SDK — a shipped surface — was never exercised by `make test`
# at all, and three of its permission-bit fault-injection tests sat undetected
# because nothing ran them. A suite that measures less than it appears to is
# the same defect class as a gate that passes vacuously.
test: ## Run unit tests with coverage
	@echo "==> Running unit tests (tags: $(or $(strip $(BUILD_TAGS)),none))..."
	@mkdir -p $(COVER_DIR)
# pipefail, or the tee at the end of the pipeline decides the exit status and
# this target can never fail — see the note on integration-test below. The Unit
# Tests CI job calls this, so without it that gate was passing by construction
# rather than on the suite's merits. (Checked: run 312's log carries zero
# failures, so nothing was actually being hidden — the hole was latent.)
	bash -o pipefail -c '$(GOTEST) $(BUILD_TAGS_FLAG) -coverprofile=$(COVER_DIR)/coverage.out \
		-covermode=atomic \
		./pkg/... ./cmd/... ./sdk/... ./test/build/... 2>&1 | tee $(BUILD_DIR)/test.log'
	@echo "==> Tests complete."

# integration-test runs E2E integration tests inside the devcontainer.
# When SIGNAL_SERVER_URL is set (inside the container), run go test directly.
# Otherwise, bring up docker-compose and run tests in the integration container.
integration-test: ## Run integration tests
ifdef SIGNAL_SERVER_URL
	@echo "==> Running integration tests against $(SIGNAL_SERVER_URL)..."
	@mkdir -p $(COVER_DIR)
	bash -o pipefail -c '$(GOTEST) -tags integration -timeout 120m \
		-coverprofile=$(COVER_DIR)/integration-coverage.out \
		-covermode=atomic \
		./test/integration/... 2>&1 | tee $(BUILD_DIR)/integration-test.log'
	@echo "==> Integration tests complete."
else
	@echo "==> Starting devcontainer infrastructure..."
	@mkdir -p $(BUILD_DIR)
	docker compose -f .devcontainer/docker-compose.yml build signal-server signal-cli integration
# `set -o pipefail` is what makes this target able to fail at all. A make recipe
# runs under /bin/sh, where a pipeline exits with the status of its LAST command
# — tee, which always succeeds — so `docker compose run` could report "dependency
# failed to start: container devcontainer-signal-server-1 exited (1)" and this
# target still returned 0. It did exactly that until 2026-08-14. bash is invoked
# explicitly because /bin/sh is dash here and has no pipefail.
	bash -o pipefail -c 'docker compose -f .devcontainer/docker-compose.yml run --rm integration 2>&1 | tee $(BUILD_DIR)/integration-test.log'
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

# test-storage-postgres runs the postgres-backed store tests against a live
# Postgres instance pointed at by TEST_POSTGRES_URL. Tests skip silently when
# the env var is unset, so this target is safe to chain into `make test`
# without pulling Postgres into the unit-test path.
#
# In the project devcontainer:
#   TEST_POSTGRES_URL=postgres://signal:signal@postgres:5432/signal?sslmode=disable
test-storage-postgres:
	$(GOTEST) -tags fido2 ./pkg/storage/postgres/...

coverage-storage-postgres:
	$(GOTEST) -tags fido2 -coverprofile=coverage-storage-postgres.out ./pkg/storage/postgres/...
	go tool cover -func=coverage-storage-postgres.out | tail -1
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

# Packages excluded from coverage reporting. Three categories, none of which
# carry hand-written business logic that unit tests should measure:
#   - generated protobuf packages (genproto/*, *pb, proto) — no logic to test
#   - main/entry-point binaries (cmd/*) — exercised via integration tests
#   - integration-only stores (storage/postgres) — its tests require a live DB,
#     so it is measured by `make integration-test`, not the unit coverage gate
COVERAGE_EXCLUDE_PATTERN := /test/|/cmd/|/genproto/|/internal/frontend|/securestorage/storagepb|/websocket/proto|/storage/postgres|/wsproto

# All testable packages (excluding test directories)
ALL_PACKAGES := $(shell go list ./... 2>/dev/null | grep -vE '$(COVERAGE_EXCLUDE_PATTERN)')

# Testable package short names for per-package targets
TESTABLE_PACKAGES := accounts api/rest api/websocket calling captcha certificates \
	config config/secrets devices directory errors keys keytransparency messages \
	profiles securestorage securevaluerecovery stickers store storage/memory \
	usernames verification websocket

.PHONY: coverage

coverage: ## Generate unit test coverage report with minimum gate
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
	@$(MAKE) --no-print-directory coverage-gate

.PHONY: coverage-gate

# coverage-gate enforces COVER_MIN against an existing profile. It is a
# separate target so the gate can be exercised against a crafted profile
# without re-running the whole suite — the reason this is worth doing is that
# the gate used to fail OPEN: `bc` given an empty percentage emitted a syntax
# error, `|| echo 0` substituted 0, and `[ 0 -eq 1 ]` passed. A run that could
# not measure coverage at all reported success.
#
# awk replaces bc: it needs no external dependency and cannot be handed an
# empty left operand, because both operands are validated before any
# comparison happens.
#
# Both, not just the measured one. COVER_MIN is command-line overridable, and
# awk's numeric coercion turns anything unparseable into 0 — which passes
# everything, the same fail-open from the other side. "90junk" would silently
# mean 90.
#
# Validation is an anchored grammar, not a character set. A character-class
# check accepts a lone "." — every character is legal — which coerces to 0 and
# waves every run through. Requiring at least one digit either side of the
# optional point is what closes that.
#
# COVERAGE_PROFILE is overridable so a test can point the gate at a fixture.
COVERAGE_PROFILE ?= $(COVER_DIR)/coverage.out

coverage-gate: ## Enforce COVER_MIN against COVERAGE_PROFILE (fails closed)
	@if ! awk -v m="$(COVER_MIN)" 'BEGIN { exit (m ~ /^[0-9]+(\.[0-9]+)?$$/) ? 0 : 1 }'; then \
		echo "FAIL: COVER_MIN is not a number ('$(COVER_MIN)') -- failing closed"; \
		exit 1; \
	fi; \
	if ! awk -v m="$(COVER_MIN)" 'BEGIN { exit (m+0 >= 0 && m+0 <= 100) ? 0 : 1 }'; then \
		echo "FAIL: COVER_MIN must be within 0-100 (got '$(COVER_MIN)') -- failing closed"; \
		exit 1; \
	fi; \
	if [ ! -s "$(COVERAGE_PROFILE)" ]; then \
		echo "FAIL: coverage profile $(COVERAGE_PROFILE) is missing or empty -- failing closed"; \
		exit 1; \
	fi; \
	TOTAL=$$(go tool cover -func="$(COVERAGE_PROFILE)" 2>/dev/null | grep '^total:' | awk '{print $$NF}'); \
	echo "=== TOTAL CODE COVERAGE: $$TOTAL ==="; \
	PCT=$$(echo "$$TOTAL" | tr -d '%'); \
	if ! awk -v p="$$PCT" 'BEGIN { exit (p ~ /^[0-9]+(\.[0-9]+)?$$/) ? 0 : 1 }'; then \
		echo "FAIL: coverage could not be measured (extracted '$$PCT') -- failing closed"; \
		exit 1; \
	fi; \
	if awk -v p="$$PCT" -v m="$(COVER_MIN)" 'BEGIN { exit (p+0 < m+0) ? 1 : 0 }'; then \
		echo "PASS: Coverage $$TOTAL meets minimum $(COVER_MIN)%"; \
	else \
		echo "FAIL: Coverage $$TOTAL is below minimum $(COVER_MIN)%"; \
		exit 1; \
	fi

.PHONY: coverage-report

coverage-report: coverage ## Generate coverage report and open it in a browser
	@which xdg-open > /dev/null 2>&1 && xdg-open $(COVER_DIR)/coverage.html || \
	which open > /dev/null 2>&1 && open $(COVER_DIR)/coverage.html || \
	echo "Coverage report generated at $(COVER_DIR)/coverage.html"

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

.PHONY: ci fmt vet lint gosec vuln modverify trivy trivy-image security

ci: fmt vet lint security build test ## Run the full CI pipeline
	@echo "==> CI pipeline complete."

fmt: ## Check gofmt formatting
	@echo "==> Checking formatting..."
	@test -z "$$($(GOFMT) -l .)" || (echo "Files need formatting:"; $(GOFMT) -l .; exit 1)

vet: ## Run go vet, under the repo's build tags and again with the integration tag
	@echo "==> Running go vet (tags: $(or $(strip $(BUILD_TAGS)),none))..."
	$(GOVET) $(BUILD_TAGS_FLAG) ./...
# Build-tagged files are invisible to the pass above, so "vet clean" could be
# true and incomplete at the same time: a file behind the `integration` tag
# once failed to compile while this target reported success. Vetting the tagged
# tree as well is what closes that hole, and it is the same masked-measurement
# class as a grep pointed at too narrow a path.
	@echo "==> Running go vet (tags: integration $(strip $(BUILD_TAGS)))..."
	$(GOVET) -tags "integration $(strip $(BUILD_TAGS))" ./...

# Both gates below take the build tags for the same reason `vet` does. Without
# them the loader cannot see a file behind //go:build, so eight packages —
# every pkg/desktop/... package and the whole of pkg/fido2, the WebAuthn
# implementation — were analysed by neither. Nothing said so: a run over ./...
# skips them and reports success, and only a run aimed AT one of them says
# "no go files to analyze".
lint: ## Run golangci-lint, under the repo's build tags
	@echo "==> Running linter (tags: $(or $(strip $(BUILD_TAGS)),none))..."
	$(GOLINT) run --timeout 5m --build-tags "$(strip $(BUILD_TAGS))" ./...

# GOSEC_FMT and GOSEC_OUT exist so CI can reuse this exact invocation while
# still producing SARIF. CI used to restate the flags in YAML, and that is how
# the scan CI actually runs came to be missing the build tags while `make
# gosec` had them — the tag set, the exclude list and the target drifted apart
# with nothing to notice. One command, one definition, is the fix.
#
# -stdout keeps findings readable in the job log when writing to a file: the
# SARIF upload only runs on github.com, so without it a Gitea failure exits 1
# with the findings buried where nobody can see them (ci-template v1.1).
GOSEC_FMT ?= text
GOSEC_OUT ?=

gosec: ## Run gosec security scanner, under the repo's build tags
	@echo "==> Running security scanner (tags: $(or $(GOSEC_TAGS),none), format: $(GOSEC_FMT))..."
	$(GOSEC) -exclude=$(GOSEC_EXCLUDE) -exclude-generated -tags "$(GOSEC_TAGS)" \
		-fmt=$(GOSEC_FMT) $(if $(GOSEC_OUT),-out=$(GOSEC_OUT) -stdout -verbose=text) ./...

vuln: ## Run govulncheck vulnerability scan
	@echo "==> Running vulnerability check..."
	$(GOVULNCHECK) ./...

modverify: ## Verify module integrity against go.sum
	@echo "==> Verifying module integrity..."
	$(GO) mod verify

# Filesystem CVE/secret scan, gated on CRITICAL/HIGH. test/ is the integration
# and performance harness; build/, bin/ and data/ are gitignored local
# artifacts. None of them ship.
trivy: ## Run trivy filesystem scan (CRITICAL/HIGH gate)
	@command -v trivy >/dev/null 2>&1 || { \
		echo "==> trivy not installed - skipping filesystem scan (see https://trivy.dev/latest/getting-started/installation/)"; \
		exit 0; \
	}; \
	echo "==> Running trivy filesystem scan..."; \
	trivy fs --scanners vuln,secret --severity CRITICAL,HIGH --exit-code 1 \
		--skip-dirs test,build,bin,data .

# Image scan of the six deploy/ service images — the artifacts
# deploy/docker-compose.yml and deploy/k8s reference.
#
# NOT a prerequisite of `security`, and deliberately so: no Dockerfile in this
# repository builds today, for two independent pre-existing reasons.
#
#   Dockerfile, Dockerfile.dev, Dockerfile.service
#     still `COPY --from=go-libsignal|go-xkms|go-qrdb|go-quicraft`, build
#     contexts only .devcontainer/docker-compose.yml supplies, so a plain
#     `docker build .` fails at the first COPY. Residue of the pre-2026-08
#     local-replace layout; go.mod itself carries no local-path replaces.
#     Removing the COPY lines would break the devcontainer compose path, so
#     the fix belongs with whoever owns that topology.
#
#   deploy/Dockerfile.*
#     build stage is golang:<stable>-alpine with no git, and the first-party
#     requires resolve from Gitea, so `go mod download` dies with
#     'exec: "git": executable file not found in $PATH' before it even gets to
#     needing GOPRIVATE and the insteadOf rewrite the host provides
#     (conventions/dependency-resolution.md).
#
# Chaining a security gate onto a build that fails for an unrelated reason
# would give this repo a gate nobody can pass. Chain this in — and add the
# matching CI job — once the Dockerfiles build.
#
# --ignore-unfixed: the runtime is gcr.io/distroless/static-debian12, whose
# package set is upstream's. A CVE with no released fix cannot be actioned by
# rebuilding; one that HAS a fix means the base is stale and is a real finding.
DEPLOY_SERVICES := signald cdsi svr2 key-transparency registration-service storage-service

trivy-image: ## Build and scan the deploy/ service images (see Makefile note)
	@command -v docker >/dev/null 2>&1 || { echo "==> docker not installed - skipping image scan"; exit 0; }; \
	command -v trivy >/dev/null 2>&1 || { echo "==> trivy not installed - skipping image scan"; exit 0; }; \
	for svc in $(DEPLOY_SERVICES); do \
		echo "==> Building and scanning go-signal-$$svc..."; \
		docker build -f deploy/Dockerfile.$$svc -t go-signal-$$svc:security . || exit 1; \
		trivy image --scanners vuln,secret --severity CRITICAL,HIGH --ignore-unfixed \
			--exit-code 1 go-signal-$$svc:security || exit 1; \
	done

# The full devops.md §8 suite. See trivy-image above for why the image scan is
# not chained in yet.
security: gosec vuln modverify trivy ## Run the full security suite
	@echo "==> Security suite passed."

# ==============================================================================
# Docker
# ==============================================================================

.PHONY: docker-build docker-build-dev docker-run docker-run-dev docker-build-services

# Production image: ships no secrets/config; requires a mounted production
# config (see configs/signal-server-prod.yml) and TLS certs at deploy time.
docker-build: ## Build production Docker image
	@echo "==> Building production Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

# Development/demo image: bakes the in-memory test config + stub transport +
# test certs for a zero-dependency `docker run`. NOT for production.
docker-build-dev: ## Build development Docker image
	@echo "==> Building development Docker image..."
	docker build -f Dockerfile.dev -t $(DOCKER_IMAGE):$(DOCKER_TAG)-dev .

# The production image fails closed without a mounted config, so the
# quick-run target uses the development image.
docker-run: docker-run-dev ## Run development Docker container

docker-run-dev:
	@echo "==> Running development Docker container..."
	docker run --rm -p 8081:8081 -p 8443:8443 $(DOCKER_IMAGE):$(DOCKER_TAG)-dev

# docker-build-services builds a Docker image for each auxiliary service
# using the shared parameterized Dockerfile.service (ARG SERVICE selects
# which ./cmd/<service> entry point to compile). Images run as non-root
# and ship no secrets or config.
docker-build-services:
	@echo "==> Building auxiliary service Docker images..."
	docker build -f Dockerfile.service --build-arg SERVICE=cdsi              -t $(DOCKER_IMAGE)-cdsi:$(DOCKER_TAG) .
	docker build -f Dockerfile.service --build-arg SERVICE=svr2              -t $(DOCKER_IMAGE)-svr2:$(DOCKER_TAG) .
	docker build -f Dockerfile.service --build-arg SERVICE=key-transparency  -t $(DOCKER_IMAGE)-key-transparency:$(DOCKER_TAG) .
	docker build -f Dockerfile.service --build-arg SERVICE=registration-service -t $(DOCKER_IMAGE)-registration-service:$(DOCKER_TAG) .
	docker build -f Dockerfile.service --build-arg SERVICE=storage-service   -t $(DOCKER_IMAGE)-storage-service:$(DOCKER_TAG) .
	@echo "==> Auxiliary service images built."

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

dev: ## Run the development server
	@echo "==> Starting development server..."
	$(GO) run ./cmd/signald/ start

deps: ## Download and tidy dependencies
	@echo "==> Downloading dependencies..."
	$(GO) mod download
	$(GO) mod tidy

clean: ## Remove build artifacts
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

# ==============================================================================
# Documentation
# ==============================================================================
#
# Documentation is a first-class deliverable. Some files are hand-written
# (ADRs, architecture/*.md, protocol/*.md) and some are generated from source
# (api/rest.md, api/grpc.md, configuration/reference.md, storage/schema-*.md).
# `make docs` regenerates generated files. `make docs-check` fails if they're
# stale. See docs/README.md for the documentation tree layout.

.PHONY: docs docs-check docs-rest docs-grpc docs-config docs-storage docs-workers

docs: docs-rest docs-grpc docs-config docs-storage docs-workers
	@echo "==> Documentation generation complete."

# Placeholder targets — each becomes a real generator as its source data lands:
#   docs-rest:    Phase 2 — emit api/rest.md from route registry in pkg/api/rest/.
#   docs-grpc:    Phase 1 — protoc-gen-doc on pkg/api/grpc/proto/*.proto → api/grpc.md.
#   docs-config:  Phase 1 — reflect over pkg/config structs → configuration/reference.md.
#   docs-storage: Phase 1 — dump table/keyspace registries → storage/schema-*.md.
#   docs-workers: Phase 1 — dump worker catalog → workers/catalog.md.
docs-rest:
	@echo "==> [docs-rest] placeholder; enabled in Phase 2."

docs-grpc:
	@echo "==> [docs-grpc] placeholder; enabled in Phase 1 (gRPC scaffold)."

docs-config:
	@echo "==> [docs-config] placeholder; enabled in Phase 1."

docs-storage:
	@echo "==> [docs-storage] placeholder; enabled in Phase 1."

docs-workers:
	@echo "==> [docs-workers] placeholder; enabled in Phase 1 (worker framework)."

docs-check: docs
	@echo "==> Checking documentation for drift..."
	@if [ -n "$$(git status --porcelain docs/ 2>/dev/null)" ]; then \
		echo "ERROR: docs/ has uncommitted changes after regeneration:"; \
		git status --porcelain docs/; \
		exit 1; \
	fi
	@echo "==> Documentation is current."

SUBMODULE_TAGS := 
# Builds never resolve through a workspace: modules come from Gitea tags
# (dependency-resolution.md §2). Immunizes against stray go.work files.
export GOWORK=off

# ---- dependency-resolution.md targets (2026-08-13 cutover) ----
# SUBMODULE_TAGS lists nested modules tagged in lockstep with the root
# (release-versioning.md P2). deps-latest runs before compiling in a
# consumer repo; release-alpha publishes this repo's next -alpha tag to dev.
# deps-latest picks the highest tag INCLUDING -alpha prereleases — bare
# 'go get @latest' ignores prereleases and would downgrade to legacy v0.0.0.

.PHONY: release-alpha deps-latest

release-alpha:
	@V=$$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || echo v0.0.0-alpha); \
	NEXT=$$(echo $$V | awk -F'[.-]' '{printf "v%s.%s.%d-alpha", substr($$1,2), $$2, $$3+1}'); \
	echo $${NEXT#v} > VERSION && git add VERSION && git commit -q -m "chore(release): $$NEXT" || true; \
	git tag $$NEXT; \
	for s in $(SUBMODULE_TAGS); do git tag "$$s/$$NEXT"; done; \
	git push dev HEAD --tags && echo "Tagged $$NEXT"

deps-latest:
	@GOWORK=off sh -c ' \
	SELF=$$(go list -m); \
	for m in $$(go list -m -f "{{if not .Indirect}}{{.Path}}{{end}}" all 2>/dev/null | grep "^github.com/jeremyhahn/" | grep -vx "$$SELF"); do \
	  case "$$(go list -m -f "{{if .Replace}}{{.Replace.Path}}{{end}}" "$$m" 2>/dev/null)" in .*|/*) continue;; esac; \
	  V=$$(go list -m -versions "$$m" 2>/dev/null | tr " " "\n" | tail -1); \
	  if [ -n "$$V" ] && [ "$$V" != "$$m" ]; then go get "$$m@$$V" || exit 1; fi; \
	done; go mod tidy'
