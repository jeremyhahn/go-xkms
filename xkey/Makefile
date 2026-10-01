# Makefile for xKey Desktop GUI
# Wails v2 desktop application with Svelte 4 + TypeScript + TailwindCSS frontend

# ==============================================================================
# Configuration
# ==============================================================================

# Builds never resolve through a workspace: modules come from Gitea tags
# (dependency-resolution.md §2). Immunizes against stray go.work files.
export GOWORK=off

# Version management (use parent VERSION file, fallback to local)
VERSION := $(shell cat ../VERSION 2>/dev/null || cat VERSION 2>/dev/null || echo "0.0.1-alpha")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Go module path for ldflags injection
LDFLAGS_PKG := github.com/jeremyhahn/go-xkms/xkey/cmd/xkey/cmd
LDFLAGS := -X $(LDFLAGS_PKG).Version=$(VERSION) \
           -X $(LDFLAGS_PKG).Commit=$(GIT_COMMIT) \
           -X $(LDFLAGS_PKG).Date=$(BUILD_DATE)

# Build tags:
#   production  - required by Wails v2 for a working GUI binary
#   ble         - enables real BLE transport (requires BlueZ/D-Bus)
#   pkcs11      - enables PKCS#11/HSM support (requires pkcs11 C headers)
#   codec_json  - enables JSON codec for go-qrdb (required for TPM blob store)
#   webkit2_41  - use webkit2gtk-4.1 (Ubuntu 24.04+ dropped 4.0)
# Auto-detect: use webkit2_41 only if 4.0 is not available
WEBKIT_TAG := $(shell pkg-config --exists webkit2gtk-4.0 2>/dev/null && echo "" || echo " webkit2_41")

# PKCS#11 support: enabled by default, set WITH_PKCS11=0 to disable
WITH_PKCS11 ?= 1
ifeq ($(WITH_PKCS11),0)
  PKCS11_TAG :=
else
  PKCS11_TAG := pkcs11
endif

# Object-storage (go-objstore) cloud backends for the embedded qrdb datastore.
# Desktop default: OFF (lean binary, no cloud SDKs). Opt in per backend (e.g.
# WITH_AWS_S3=1) or per provider (WITH_AWS=1). Tag names match go-objstore.
WITH_AWS_S3        ?= 0
WITH_MINIO         ?= 0
WITH_GCP_STORAGE   ?= 0
WITH_AZURE_BLOB    ?= 0
WITH_GLACIER       ?= 0
WITH_AZURE_ARCHIVE ?= 0
WITH_AWS   ?= 0
WITH_GCP   ?= 0
WITH_AZURE ?= 0
ifeq ($(WITH_AWS),1)
  WITH_AWS_S3 := 1
  WITH_GLACIER := 1
endif
ifeq ($(WITH_GCP),1)
  WITH_GCP_STORAGE := 1
endif
ifeq ($(WITH_AZURE),1)
  WITH_AZURE_BLOB := 1
  WITH_AZURE_ARCHIVE := 1
endif
OBJSTORE_TAGS :=
ifeq ($(WITH_AWS_S3),1)
  OBJSTORE_TAGS += awss3
endif
ifeq ($(WITH_MINIO),1)
  OBJSTORE_TAGS += minio
endif
ifeq ($(WITH_GCP_STORAGE),1)
  OBJSTORE_TAGS += gcpstorage
endif
ifeq ($(WITH_AZURE_BLOB),1)
  OBJSTORE_TAGS += azureblob
endif
ifeq ($(WITH_GLACIER),1)
  OBJSTORE_TAGS += glacier
endif
ifeq ($(WITH_AZURE_ARCHIVE),1)
  OBJSTORE_TAGS += azurearchive
endif

BUILD_TAGS := ble production codec_json $(PKCS11_TAG)$(WEBKIT_TAG) $(OBJSTORE_TAGS)

# Development tags: exclude "production" because the Wails CLI injects the
# "dev" tag automatically during `wails dev`, and wails's internal app
# package has separate files guarded by //go:build dev and //go:build
# production that each declare App.Run and CreateApp. Including both tags
# produces "method App.Run already declared" at link time.
DEV_TAGS := ble codec_json $(PKCS11_TAG)$(WEBKIT_TAG) $(OBJSTORE_TAGS)

# Unit test tags: exclude "ble" so BLE stub is used (fast, no hardware).
# The ble tag enables real bluetooth.DefaultAdapter.Enable() which blocks
# ~25s on machines without BLE hardware. Integration tests use BUILD_TAGS
# (with ble) for real hardware testing in the devcontainer.
# Note: PKCS#11 is included in test tags since it doesn't require hardware for unit tests.
# tpm_simulator runs the TPM tests on the in-process simulator (no device).
TEST_TAGS := production codec_json tpm_simulator $(PKCS11_TAG)$(WEBKIT_TAG) $(OBJSTORE_TAGS)

# Go parameters
GO := go
GOBUILD := $(GO) build -buildvcs=false -tags "$(BUILD_TAGS)" -ldflags "$(LDFLAGS)"
GOCLEAN := $(GO) clean
GOTEST := $(GO) test -tags "$(TEST_TAGS)"
GOVET := $(GO) vet -tags "$(BUILD_TAGS)"
GOFMT := gofmt

# Project structure
MODULE := github.com/jeremyhahn/go-xkms/xkey
PROJECT_ROOT := $(CURDIR)
WORKSPACE_ROOT := $(PROJECT_ROOT)/..
SOURCES_ROOT := $(realpath $(WORKSPACE_ROOT)/..)
FRONTEND_DIR := $(PROJECT_ROOT)/frontend

# Build artifacts
BUILD_DIR := build
# The xkey binary is written directly to the top-level go-xkms build/bin/
# directory so there is a single authoritative output location for the
# whole project (overridable via `make BIN_DIR=...`). BUILD_DIR itself
# stays under xkey/ for coverage and benchmark artefacts.
BIN_DIR ?= $(WORKSPACE_ROOT)/build/bin
COVERAGE_DIR := $(BUILD_DIR)/coverage

# Docker builder image — all CGO deps (webkit, libusb, bluetooth, Node.js)
# are baked in so builds work on any machine with Docker.
BUILDER_IMAGE := go-xkms-xkey-builder:latest

# Tool binaries
WAILS := $(shell command -v wails 2>/dev/null)
NPM := $(shell command -v npm 2>/dev/null)
GOLANGCI_LINT := $(shell command -v golangci-lint 2>/dev/null || echo "$(HOME)/go/bin/golangci-lint")

# Frontend tool paths — invoke via node directly to avoid Node.js ESM symlink
# resolution bugs in .bin/ shims (affects Node 24.13+).
VITE := node $(FRONTEND_DIR)/node_modules/vite/bin/vite.js
SVELTE_CHECK := node $(FRONTEND_DIR)/node_modules/svelte-check/bin/svelte-check
VITEST := node $(FRONTEND_DIR)/node_modules/vitest/vitest.mjs

# Test configuration
TEST_FLAGS := -v -race
COVERAGE_FILE := $(COVERAGE_DIR)/coverage.out
COVERAGE_HTML := $(COVERAGE_DIR)/coverage.html
COVERAGE_THRESHOLD := 90

# Integration test flags include tpm_simulator so the in-process TPM
# simulator (CGO, MS TPM reference implementation) is available for tests.
# This is NOT included in BUILD_TAGS because it requires OpenSSL headers.
INTEGRATION_TEST_FLAGS := -v -tags="integration linux tpm_simulator $(BUILD_TAGS)"

# Export the production tag set for tests that build the CLI binary
# themselves (test/integration buildBinary). Without it the test-built
# binary lacks codec_json and the go-codec based DAOs fail at runtime.
# tpm_simulator is appended (never added to BUILD_TAGS itself) so the
# CLI-under-test can open the in-process TPM simulator, matching the test
# binary's own INTEGRATION_TEST_FLAGS above. Without this, "xkey barrier
# init --strategy tpm2 --tpm-simulator" would fail to link the simulator
# and integration tests would silently fall through to the real host TPM.
export XKEY_CLI_BUILD_TAGS := $(BUILD_TAGS) tpm_simulator

# Color output (ANSI escape codes)
RESET := \033[0m
BOLD := \033[1m
RED := \033[31m
GREEN := \033[32m
YELLOW := \033[33m
BLUE := \033[34m
CYAN := \033[36m

# ==============================================================================
# Default Target
# ==============================================================================

.DEFAULT_GOAL := build

# ==============================================================================
# Primary Build Targets
# ==============================================================================

.PHONY: build
## build: Build the xkey binary with embedded frontend (GUI + CLI in one)
## Uses Docker to ensure all CGO dependencies (webkit, libusb, bluetooth) are available.
build: builder-image
	@echo "$(CYAN)$(BOLD)Building xKey frontend...$(RESET)"
	@docker run --rm \
		-v $(SOURCES_ROOT):/sources:cached \
		-w /sources/go-xkms/xkey/frontend \
		$(BUILDER_IMAGE) \
		bash -c "npm ci --silent && node ./node_modules/vite/bin/vite.js build"
	@echo "$(CYAN)$(BOLD)Building browser extension...$(RESET)"
	@docker run --rm \
		-v $(SOURCES_ROOT):/sources:cached \
		-w /sources/go-xkms/xkey/extension \
		$(BUILDER_IMAGE) \
		bash -c "set -e && rm -rf node_modules && npm ci --silent && node node_modules/typescript/lib/tsc.js && cp manifest.json dist/ && cp src/popup.html dist/ && mkdir -p dist/icons && (cp -r src/icons/* dist/icons/ 2>/dev/null || true)"
	@echo "$(CYAN)$(BOLD)Building xKey binary...$(RESET)"
	@mkdir -p $(BIN_DIR)
	@docker run --rm \
		-v $(SOURCES_ROOT):/sources:cached \
		-w /sources/go-xkms/xkey \
		$(BUILDER_IMAGE) \
		bash -c "CGO_ENABLED=1 go build -buildvcs=false -tags '$(BUILD_TAGS)' -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/xkey ./cmd/xkey"
	@echo "$(GREEN)Binary built: $(BIN_DIR)/xkey$(RESET)"
	@echo "$(GREEN)  Run with GUI:  ./$(BIN_DIR)/xkey$(RESET)"
	@echo "$(GREEN)  Run as CLI:    ./$(BIN_DIR)/xkey --no-gui$(RESET)"

.PHONY: builder-image
## builder-image: Build the Docker builder image with all CGO dependencies
builder-image:
	@echo "$(CYAN)$(BOLD)Building builder image...$(RESET)"
	@DOCKER_BUILDKIT=0 docker build -q -t $(BUILDER_IMAGE) -f Dockerfile.builder . >/dev/null

.PHONY: build-local
## build-local: Build xkey locally (requires webkit, libusb, bluetooth dev packages)
build-local: frontend-build extension-build
	@echo "$(CYAN)$(BOLD)Building xKey (local)...$(RESET)"
	@mkdir -p $(BIN_DIR)
	@CGO_ENABLED=1 $(GOBUILD) -o $(BIN_DIR)/xkey ./cmd/xkey
	@echo "$(GREEN)Binary built: $(BIN_DIR)/xkey$(RESET)"
	@echo "$(GREEN)  Run with GUI:  ./$(BIN_DIR)/xkey$(RESET)"
	@echo "$(GREEN)  Run as CLI:    ./$(BIN_DIR)/xkey --no-gui$(RESET)"

.PHONY: dev
## dev: Development mode with Wails hot reload (frontend + backend)
dev: frontend-install
	@echo "$(CYAN)$(BOLD)Starting xKey development server...$(RESET)"
	@GODEBUG=gotypesalias=1 wails dev -tags "$(DEV_TAGS)" -ldflags "$(LDFLAGS)"

.PHONY: dev-browser
## dev-browser: Development mode serving at http://localhost:34115 for Playwright live-backend tests
dev-browser: frontend-install
	@echo "$(CYAN)$(BOLD)Starting xKey dev (browser mode) on :34115...$(RESET)"
	@# GODEBUG=gotypesalias=1 forces go/types to materialize type aliases;
	@# wails v2.12.0 is built with gotypesalias=0 baked in which trips
	@# x/tools/go/packages when a bound package imports parameterized
	@# type aliases (e.g. qrdbsdk.PageResult[E]) from go-qrdb/sdk/go.
	@# -nosyncgomod + -m skip 'go mod tidy'. First-party deps resolve from
	@# Gitea tags (dependency-resolution.md); no workspace is used.
	@GODEBUG=gotypesalias=1 wails dev -browser -nosyncgomod -m -tags "$(DEV_TAGS)" -ldflags "$(LDFLAGS)"

# Hermetic sandbox dirs used by dev-browser-e2e. Override on the command line
# if you want a different location, e.g. make dev-browser-e2e E2E_HOME=/mnt/...
E2E_HOME        ?= /tmp/xkey-e2e-home
E2E_CONFIG      ?= /tmp/xkey-e2e-config
E2E_SOFTHSM_DIR ?= /tmp/xkey-e2e-softhsm

.PHONY: e2e-softhsm-setup
## e2e-softhsm-setup: Idempotently provision a sandboxed SoftHSM2 token (e2e-piv-test) with PIV certs for dev-browser-e2e
## Entirely isolated under $(E2E_SOFTHSM_DIR) via a dedicated SOFTHSM2_CONF — never reads/writes the host ~/.config/softhsm2.
e2e-softhsm-setup:
	@E2E_SOFTHSM_DIR="$(E2E_SOFTHSM_DIR)" bash scripts/e2e-softhsm-setup.sh

.PHONY: dev-browser-e2e
## dev-browser-e2e: Hermetic browser-mode server for Playwright live-backend tests (isolated XKEY_HOME + XDG_CONFIG_HOME + SOFTHSM2_CONF)
## Uses /tmp/xkey-e2e-home, /tmp/xkey-e2e-config, and /tmp/xkey-e2e-softhsm so the real ~/.config/xkey and ~/.config/softhsm2 are never touched.
## Run dev-browser-e2e-clean first to reset the sandbox to a fresh first-run state.
dev-browser-e2e: frontend-install e2e-softhsm-setup
	@echo "$(CYAN)$(BOLD)Starting xKey dev (e2e hermetic mode) on :34115...$(RESET)"
	@echo "$(YELLOW)XKEY_HOME=$(E2E_HOME)  XDG_CONFIG_HOME=$(E2E_CONFIG)  SOFTHSM2_CONF=$(E2E_SOFTHSM_DIR)/softhsm2.conf$(RESET)"
	@mkdir -p "$(E2E_HOME)" "$(E2E_CONFIG)"
	@# See dev-browser comment above for GODEBUG and -nosyncgomod rationale.
	@XKEY_HOME="$(E2E_HOME)" XDG_CONFIG_HOME="$(E2E_CONFIG)" SOFTHSM2_CONF="$(E2E_SOFTHSM_DIR)/softhsm2.conf" \
		GODEBUG=gotypesalias=1 wails dev -browser -nosyncgomod -m -tags "$(DEV_TAGS)" -ldflags "$(LDFLAGS)"

.PHONY: dev-browser-e2e-clean
## dev-browser-e2e-clean: Wipe the e2e sandbox dirs so the next dev-browser-e2e run boots into the first-run wizard
dev-browser-e2e-clean:
	@echo "$(YELLOW)Removing e2e sandbox: $(E2E_HOME) and $(E2E_CONFIG)/xkey$(RESET)"
	@rm -rf "$(E2E_HOME)" "$(E2E_CONFIG)/xkey"
	@echo "$(GREEN)E2E sandbox cleared. Next dev-browser-e2e run starts fresh.$(RESET)"

# ==============================================================================
# Frontend Targets
# ==============================================================================

.PHONY: frontend-install
## frontend-install: Install frontend npm dependencies
frontend-install:
	@echo "$(CYAN)Installing frontend dependencies...$(RESET)"
	@cd $(FRONTEND_DIR) && npm ci
	@echo "$(GREEN)Frontend dependencies installed$(RESET)"

.PHONY: frontend-build
## frontend-build: Build frontend for production (installs deps if needed)
frontend-build: frontend-install
	@echo "$(CYAN)Building frontend...$(RESET)"
	@cd $(FRONTEND_DIR) && $(VITE) build
	@echo "$(GREEN)Frontend built$(RESET)"

.PHONY: frontend-dev
## frontend-dev: Start frontend development server
frontend-dev: frontend-install
	@echo "$(CYAN)Starting frontend development server...$(RESET)"
	@cd $(FRONTEND_DIR) && $(VITE) dev

.PHONY: frontend-check
## frontend-check: Run svelte-check for type checking
frontend-check: frontend-install
	@echo "$(CYAN)Running svelte-check...$(RESET)"
	@cd $(FRONTEND_DIR) && $(SVELTE_CHECK) --tsconfig ./tsconfig.json
	@echo "$(GREEN)Frontend type checks passed$(RESET)"

.PHONY: frontend-test
## frontend-test: Run frontend unit tests (vitest)
frontend-test: frontend-install
	@echo "$(CYAN)Running frontend unit tests...$(RESET)"
	@cd $(FRONTEND_DIR) && $(VITEST) run
	@echo "$(GREEN)Frontend unit tests passed$(RESET)"

.PHONY: frontend-test-coverage
## frontend-test-coverage: Run frontend unit tests with coverage (vitest)
frontend-test-coverage: frontend-install
	@echo "$(CYAN)Running frontend unit tests with coverage...$(RESET)"
	@cd $(FRONTEND_DIR) && $(VITEST) run --coverage
	@echo "$(GREEN)Frontend unit test coverage report generated$(RESET)"

# ==============================================================================
# Extension Targets
# ==============================================================================

EXTENSION_DIR := $(PROJECT_ROOT)/extension

.PHONY: extension-build extension-build-chrome extension-build-firefox
## extension-build: Build browser extension for Chrome (default)
extension-build: extension-build-chrome

## extension-build-chrome: Build browser extension for Chrome → extension/dist/
extension-build-chrome:
	@echo "$(CYAN)Building browser extension (Chrome)...$(RESET)"
	@cd $(EXTENSION_DIR) && ./build.sh chrome
	@echo "$(GREEN)Chrome extension built: extension/dist/$(RESET)"

## extension-build-firefox: Build browser extension for Firefox → extension/dist-firefox/ + .xpi
extension-build-firefox:
	@echo "$(CYAN)Building browser extension (Firefox)...$(RESET)"
	@cd $(EXTENSION_DIR) && ./build.sh firefox
	@echo "$(GREEN)Firefox extension built: extension/dist-firefox/ + extension/xkey-autofill.xpi$(RESET)"

# ==============================================================================
# Test Targets
# ==============================================================================

.PHONY: test
## test: Run all unit tests with coverage
# Unit tests never reach the host's hardware TPM (go-xkms pkg/tpm2/tpmdev):
# this flag holds every process a test runs to that rule too. Opt in with
# XKMS_TEST_HARDWARE_TPM=1.
test: export XKMS_DENY_HARDWARE_TPM := 1
test:
	@echo "$(CYAN)$(BOLD)Running unit tests...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) $(TEST_FLAGS) \
		-coverprofile=$(COVERAGE_FILE) \
		-covermode=atomic \
		./cmd/... ./pkg/...
	@$(GO) tool cover -func=$(COVERAGE_FILE) | tail -1
	@echo "$(GREEN)Unit tests passed$(RESET)"

.PHONY: test-gui
## test-gui: Run GUI service tests specifically
test-gui:
	@echo "$(CYAN)Running GUI service tests...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/gui/...
	@echo "$(GREEN)GUI service tests passed$(RESET)"

.PHONY: test-authenticator
## test-authenticator: Run authenticator package unit tests
test-authenticator:
	@echo "$(CYAN)Running authenticator tests...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/authenticator/...
	@echo "$(GREEN)Authenticator tests passed$(RESET)"

.PHONY: test-uhid
## test-uhid: Run UHID package unit tests
test-uhid:
	@echo "$(CYAN)Running UHID tests...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/uhid/...
	@echo "$(GREEN)UHID tests passed$(RESET)"

.PHONY: test-ipc
## test-ipc: Run IPC package unit tests
test-ipc:
	@echo "$(CYAN)Running IPC tests...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/ipc/...
	@echo "$(GREEN)IPC tests passed$(RESET)"

.PHONY: test-keyboard
## test-keyboard: Run keyboard package unit tests
test-keyboard:
	@echo "$(CYAN)Running keyboard tests...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/keyboard/...
	@echo "$(GREEN)Keyboard tests passed$(RESET)"

.PHONY: test-notify
## test-notify: Run notification package unit tests
test-notify:
	@echo "$(CYAN)Running notification tests...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/notify/...
	@echo "$(GREEN)Notification tests passed$(RESET)"

.PHONY: test-staticpw
## test-staticpw: Run static password package unit tests
test-staticpw:
	@echo "$(CYAN)Running static password tests...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/staticpw/...
	@echo "$(GREEN)Static password tests passed$(RESET)"

.PHONY: test-oath
## test-oath: Run OATH (TOTP/HOTP) package unit tests
test-oath:
	@echo "$(CYAN)Running OATH tests...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/oath/...
	@echo "$(GREEN)OATH tests passed$(RESET)"

.PHONY: test-phone
## test-phone: Run phone package unit tests
test-phone:
	@echo "$(CYAN)Running phone tests...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/phone/...
	@echo "$(GREEN)Phone tests passed$(RESET)"

.PHONY: test-oidc
## test-oidc: Run OIDC package unit tests
test-oidc:
	@echo "$(CYAN)Running OIDC tests...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/oidc/...
	@echo "$(GREEN)OIDC tests passed$(RESET)"

.PHONY: test-ssh
## test-ssh: Run SSH package unit tests
test-ssh:
	@echo "$(CYAN)Running SSH tests...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/ssh/...
	@echo "$(GREEN)SSH tests passed$(RESET)"

.PHONY: test-virtualdevice
## test-virtualdevice: Run virtual device package unit tests
test-virtualdevice:
	@echo "$(CYAN)Running virtual device tests...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/virtualdevice/...
	@echo "$(GREEN)Virtual device tests passed$(RESET)"

.PHONY: test-gadget
## test-gadget: Run USB gadget package unit tests
test-gadget:
	@echo "$(CYAN)Running USB gadget tests...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/gadget/...
	@echo "$(GREEN)USB gadget tests passed$(RESET)"

.PHONY: test-ccid
## test-ccid: Run CCID package unit tests
test-ccid:
	@echo "$(CYAN)Running CCID tests...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/ccid/...
	@echo "$(GREEN)CCID tests passed$(RESET)"

.PHONY: playwright-test
## playwright-test: Run Playwright GUI tests (devcontainer with Wails)
playwright-test:
	@echo "$(CYAN)$(BOLD)Running Playwright GUI tests...$(RESET)"
	@cd $(FRONTEND_DIR) && npx playwright test
	@echo "$(GREEN)Playwright tests passed$(RESET)"

.PHONY: playwright-test-vite
## playwright-test-vite: Run Playwright GUI tests against Vite dev server (port 5173)
playwright-test-vite:
	@echo "$(CYAN)$(BOLD)Running Playwright GUI tests (Vite)...$(RESET)"
	@cd $(FRONTEND_DIR) && BASE_URL=http://localhost:5173 npx playwright test
	@echo "$(GREEN)Playwright tests passed$(RESET)"

.PHONY: integration-test
## integration-test: Run ALL integration tests (requires devcontainer)
integration-test: integration-test-cli integration-test-fido2 integration-test-uhid \
	integration-test-phone integration-test-oath integration-test-password \
	integration-test-piv integration-test-ssh integration-test-touch \
	integration-test-oidc integration-test-luks integration-test-extension \
	integration-test-gadget integration-test-ble integration-test-tpm
	@echo "$(GREEN)$(BOLD)All integration tests passed$(RESET)"

.PHONY: integration-test-tpm
## integration-test-tpm: Run TPMService integration tests against the in-process TPM simulator
# The suite lives beside the service it exercises (pkg/gui/services) and is
# guarded by `//go:build integration && tpm_simulator`. INTEGRATION_TEST_FLAGS
# supplies both tags plus CGO, so the simulator links in and NO host TPM
# character device is opened.
integration-test-tpm:
	@echo "$(CYAN)$(BOLD)Running TPM service integration tests (simulator)...$(RESET)"
	@$(GO) test $(INTEGRATION_TEST_FLAGS) -timeout=15m -run 'TestIntegration_TPMService' ./pkg/gui/services/
	@echo "$(GREEN)TPM service integration tests passed$(RESET)"

.PHONY: integration-test-cli
## integration-test-cli: Run CLI, passkey, and backend integration tests
integration-test-cli:
	@echo "$(CYAN)$(BOLD)Running CLI integration tests...$(RESET)"
	@$(GO) test $(INTEGRATION_TEST_FLAGS) -timeout=10m ./test/integration/
	@echo "$(GREEN)CLI integration tests passed$(RESET)"

.PHONY: integration-test-fido2
## integration-test-fido2: Run FIDO2/CTAP2 integration tests
integration-test-fido2:
	@echo "$(CYAN)$(BOLD)Running FIDO2 integration tests...$(RESET)"
	@$(GO) test $(INTEGRATION_TEST_FLAGS) -timeout=10m ./test/integration/fido2/...
	@# FIDO2 key-backend adapter matrix (software + cloud KMS via mocks; the
	@# TPM2 host entry is opt-in via XKEY_ALLOW_HOST_TPM and skips here). Runs in
	@# the devcontainer with INTEGRATION_TEST_FLAGS (includes tpm_simulator), so
	@# no host hardware is touched by default.
	@$(GO) test $(INTEGRATION_TEST_FLAGS) -timeout=10m ./pkg/authenticator/keybackend/...
	@echo "$(GREEN)FIDO2 integration tests passed$(RESET)"

.PHONY: integration-test-uhid
## integration-test-uhid: Run UHID virtual device integration tests
integration-test-uhid:
	@echo "$(CYAN)$(BOLD)Running UHID integration tests...$(RESET)"
	@$(GO) test $(INTEGRATION_TEST_FLAGS) -timeout=10m ./test/integration/uhid/...
	@echo "$(GREEN)UHID integration tests passed$(RESET)"

.PHONY: integration-test-phone
## integration-test-phone: Run phone/device pairing integration tests
integration-test-phone:
	@echo "$(CYAN)$(BOLD)Running phone integration tests...$(RESET)"
	@$(GO) test $(INTEGRATION_TEST_FLAGS) -timeout=10m ./test/integration/phone/...
	@echo "$(GREEN)Phone integration tests passed$(RESET)"

.PHONY: integration-test-phone-tcp
## integration-test-phone-tcp: Run Go TCP E2E tests (MockPhone over real TCP)
integration-test-phone-tcp:
	@echo "$(CYAN)$(BOLD)Running phone TCP E2E integration tests...$(RESET)"
	@$(GO) test $(INTEGRATION_TEST_FLAGS) -timeout=10m -run TestTCPE2E ./test/integration/phone/...
	@echo "$(GREEN)Phone TCP E2E tests passed$(RESET)"

.PHONY: integration-test-phone-android
## integration-test-phone-android: Run Go ↔ real Android app E2E tests (Docker emulator)
integration-test-phone-android:
	@echo "$(CYAN)$(BOLD)Starting Android emulator E2E tests...$(RESET)"
	@docker compose -f test/integration/phone/docker-compose.yml up --build --abort-on-container-exit --exit-code-from test-runner
	@echo "$(GREEN)Android E2E tests passed$(RESET)"

.PHONY: integration-test-oath
## integration-test-oath: Run OATH (TOTP/HOTP) integration tests
integration-test-oath:
	@echo "$(CYAN)$(BOLD)Running OATH integration tests...$(RESET)"
	@$(GO) test $(INTEGRATION_TEST_FLAGS) -timeout=10m ./test/integration/oath/...
	@echo "$(GREEN)OATH integration tests passed$(RESET)"

.PHONY: integration-test-password
## integration-test-password: Run password integration tests
integration-test-password:
	@echo "$(CYAN)$(BOLD)Running password integration tests...$(RESET)"
	@$(GO) test $(INTEGRATION_TEST_FLAGS) -timeout=10m ./test/integration/password/...
	@echo "$(GREEN)Password integration tests passed$(RESET)"

.PHONY: integration-test-piv
## integration-test-piv: Run PIV smart card integration tests
integration-test-piv:
	@echo "$(CYAN)$(BOLD)Running PIV integration tests...$(RESET)"
	@$(GO) test $(INTEGRATION_TEST_FLAGS) -timeout=10m ./test/integration/piv/...
	@echo "$(GREEN)PIV integration tests passed$(RESET)"

.PHONY: integration-test-piv-yubikey
## integration-test-piv-yubikey: Run PIV YubiKey integration tests (requires stock YubiKey plugged in)
integration-test-piv-yubikey:
	@echo "$(CYAN)$(BOLD)Running PIV YubiKey integration tests...$(RESET)"
	@$(GO) test -v -tags="integration pkcs11 yubikey $(BUILD_TAGS)" -count=1 -timeout=60m ./test/integration/piv/... -run 'TestYubiKey'
	@echo "$(GREEN)PIV YubiKey integration tests passed$(RESET)"

# NOTE: There are no OATH or FIDO2 YubiKey integration targets because xkey has
# no YubiKey backend for either capability yet:
#   - xkey oath routes every command through oath.NewFileStore; there is no
#     CCID OATH applet client and no --backend yubikey flag.
#   - xkey fido2 is a virtual CTAP2 authenticator over UHID; --backend accepts
#     only software/tpm2/phone, with no pass-through to a physical YubiKey.
# The placeholder suites that used to sit here contained only unconditional
# t.Skip calls, so they asserted nothing while implying YubiKey coverage
# existed. Add the backends first, then add real suites and targets.

.PHONY: integration-test-yubikey
## integration-test-yubikey: Run ALL YubiKey hardware integration tests (PIV) — NOT part of global integration-test
integration-test-yubikey: integration-test-piv-yubikey
	@echo "$(GREEN)$(BOLD)All YubiKey hardware integration tests passed$(RESET)"

.PHONY: integration-test-ssh
## integration-test-ssh: Run SSH agent integration tests
integration-test-ssh:
	@echo "$(CYAN)$(BOLD)Running SSH integration tests...$(RESET)"
	@$(GO) test $(INTEGRATION_TEST_FLAGS) -timeout=10m ./test/integration/ssh/...
	@echo "$(GREEN)SSH integration tests passed$(RESET)"

.PHONY: integration-test-touch
## integration-test-touch: Run touch/biometric integration tests
integration-test-touch:
	@echo "$(CYAN)$(BOLD)Running touch integration tests...$(RESET)"
	@$(GO) test $(INTEGRATION_TEST_FLAGS) -timeout=10m ./test/integration/touch/...
	@echo "$(GREEN)Touch integration tests passed$(RESET)"

.PHONY: integration-test-oidc
## integration-test-oidc: Run OIDC integration tests with Hydra (via docker-compose)
integration-test-oidc:
	@echo "$(CYAN)$(BOLD)Running OIDC integration tests with Hydra...$(RESET)"
	@docker compose -f test/integration/oidc/docker-compose.yml up --build --abort-on-container-exit --exit-code-from test-runner
	@echo "$(GREEN)OIDC integration tests passed$(RESET)"

.PHONY: integration-test-luks
## integration-test-luks: Run LUKS integration tests (requires root + dm-crypt)
integration-test-luks:
	@echo "$(CYAN)$(BOLD)Running LUKS integration tests...$(RESET)"
	@$(GO) test $(INTEGRATION_TEST_FLAGS) -timeout=10m ./test/integration/luks/...
	@echo "$(GREEN)LUKS integration tests passed$(RESET)"

.PHONY: integration-test-setup
## integration-test-setup: Run setup wizard integration tests (requires devcontainer)
integration-test-setup:
	@echo "$(CYAN)$(BOLD)Running setup wizard integration tests...$(RESET)"
	@$(GO) test $(INTEGRATION_TEST_FLAGS) -timeout=5m ./test/integration/ -run "TestCLI_Pin|TestCLI_Barrier|TestCLI_Password"
	@echo "$(GREEN)Setup wizard integration tests passed$(RESET)"

.PHONY: integration-test-setup-tpm
## integration-test-setup-tpm: Run setup wizard TPM integration tests (requires devcontainer with swtpm)
integration-test-setup-tpm:
	@echo "$(CYAN)$(BOLD)Running setup wizard TPM integration tests...$(RESET)"
	@$(GO) test $(INTEGRATION_TEST_FLAGS) -timeout=5m ./test/integration/ -run "TestCLI_.*TPM"
	@echo "$(GREEN)Setup wizard TPM integration tests passed$(RESET)"

.PHONY: integration-test-extension
## integration-test-extension: Run browser extension E2E integration tests (Docker + Playwright)
integration-test-extension:
	@echo "$(CYAN)$(BOLD)Running browser extension E2E integration tests...$(RESET)"
	@docker compose -f test/integration/extension/docker-compose.yml up --build --abort-on-container-exit --exit-code-from extension-test
	@echo "$(GREEN)Browser extension E2E tests passed$(RESET)"

.PHONY: integration-test-gadget
## integration-test-gadget: Run USB gadget integration tests (requires privileged Docker)
integration-test-gadget:
	@echo "$(CYAN)$(BOLD)Running USB gadget integration tests...$(RESET)"
	@docker compose -f test/integration/gadget/docker-compose.yml up --build --abort-on-container-exit --exit-code-from gadget-tests
	@echo "$(GREEN)USB gadget integration tests passed$(RESET)"

.PHONY: integration-test-ble
## integration-test-ble: Run virtual-hardware BLE integration tests (privileged Docker + host netns)
integration-test-ble:
	@echo "$(CYAN)$(BOLD)Running BLE integration tests (virtual HCI controllers)...$(RESET)"
	@docker compose -f test/integration/ble/docker-compose.yml up --build --abort-on-container-exit --exit-code-from ble-tests
	@echo "$(GREEN)BLE integration tests passed$(RESET)"

# ==============================================================================
# Coverage Targets
# ==============================================================================

.PHONY: coverage
## coverage: Generate aggregate coverage report for all xkey packages
coverage:
	@echo "$(CYAN)$(BOLD)Generating aggregate coverage report...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race \
		-coverprofile=$(COVERAGE_FILE) \
		-covermode=atomic \
		./cmd/... ./pkg/...
	@$(GO) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@$(GO) tool cover -func=$(COVERAGE_FILE) | tail -1
	@echo "$(GREEN)Coverage report: $(COVERAGE_HTML)$(RESET)"

.PHONY: coverage-full
## coverage-full: Generate comprehensive coverage (unit + integration tests)
coverage-full:
	@echo "$(CYAN)$(BOLD)Running comprehensive coverage (unit + integration)...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)Step 1: Running unit tests with coverage...$(RESET)"
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/unit.out -covermode=atomic \
		./cmd/... ./pkg/... 2>&1 | tee $(COVERAGE_DIR)/unit.log; \
		unit_exit=$$?; \
		if [ ! -f "$(COVERAGE_DIR)/unit.out" ] || [ ! -s "$(COVERAGE_DIR)/unit.out" ]; then \
			echo "$(RED)✗ Unit test coverage profile missing or empty$(RESET)"; \
			exit 1; \
		fi; \
		if [ $$unit_exit -ne 0 ]; then exit $$unit_exit; fi
	@echo "$(CYAN)Step 2: Running integration tests with coverage...$(RESET)"
	@$(GO) test $(INTEGRATION_TEST_FLAGS) -race \
		-coverprofile=$(COVERAGE_DIR)/integration.out -covermode=atomic \
		./test/integration/... 2>&1 | tee $(COVERAGE_DIR)/integration.log; \
		integration_exit=$$?; \
		if [ ! -f "$(COVERAGE_DIR)/integration.out" ] || [ ! -s "$(COVERAGE_DIR)/integration.out" ]; then \
			echo "$(RED)✗ Integration test coverage profile missing or empty$(RESET)"; \
			exit 1; \
		fi; \
		if [ $$integration_exit -ne 0 ]; then exit $$integration_exit; fi
	@echo "$(CYAN)Step 3: Merging coverage profiles...$(RESET)"
	@echo "mode: atomic" > $(COVERAGE_FILE)
	@tail -n +2 $(COVERAGE_DIR)/unit.out >> $(COVERAGE_FILE) 2>/dev/null || true
	@tail -n +2 $(COVERAGE_DIR)/integration.out >> $(COVERAGE_FILE) 2>/dev/null || true
	@$(GO) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@$(GO) tool cover -func=$(COVERAGE_FILE) | tail -1
	@echo "$(GREEN)$(BOLD)Comprehensive coverage report: $(COVERAGE_HTML)$(RESET)"

.PHONY: coverage-gui
## coverage-gui: Generate code coverage report for pkg/gui/
coverage-gui:
	@echo "$(CYAN)Generating GUI coverage report...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/gui.out -covermode=atomic ./pkg/gui/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/gui.out -o $(COVERAGE_DIR)/gui.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/gui.out | tail -1
	@echo "$(GREEN)Coverage report: $(COVERAGE_DIR)/gui.html$(RESET)"

.PHONY: coverage-authenticator
## coverage-authenticator: Generate authenticator package coverage report
coverage-authenticator:
	@echo "$(CYAN)Generating authenticator coverage report...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/authenticator.out -covermode=atomic ./pkg/authenticator/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/authenticator.out -o $(COVERAGE_DIR)/authenticator.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/authenticator.out | tail -1
	@echo "$(GREEN)Coverage report: $(COVERAGE_DIR)/authenticator.html$(RESET)"

.PHONY: coverage-uhid
## coverage-uhid: Generate UHID package coverage report
coverage-uhid:
	@echo "$(CYAN)Generating UHID coverage report...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/uhid.out -covermode=atomic ./pkg/uhid/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/uhid.out -o $(COVERAGE_DIR)/uhid.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/uhid.out | tail -1
	@echo "$(GREEN)Coverage report: $(COVERAGE_DIR)/uhid.html$(RESET)"

.PHONY: coverage-gadget
## coverage-gadget: Run USB gadget tests with coverage report
coverage-gadget:
	@echo "$(CYAN)Running USB gadget coverage...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -coverprofile=$(COVERAGE_DIR)/gadget-coverage.out -covermode=atomic ./pkg/gadget/...
	@$(GO) tool cover -func=$(COVERAGE_DIR)/gadget-coverage.out | tail -1
	@echo "$(GREEN)USB gadget coverage complete$(RESET)"

.PHONY: coverage-ccid
## coverage-ccid: Run CCID tests with coverage report
coverage-ccid:
	@echo "$(CYAN)Running CCID coverage...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -coverprofile=$(COVERAGE_DIR)/ccid-coverage.out -covermode=atomic ./pkg/ccid/...
	@$(GO) tool cover -func=$(COVERAGE_DIR)/ccid-coverage.out | tail -1
	@echo "$(GREEN)CCID coverage complete$(RESET)"

.PHONY: coverage-ipc
## coverage-ipc: Generate IPC package coverage report
coverage-ipc:
	@echo "$(CYAN)Generating IPC coverage report...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/ipc.out -covermode=atomic ./pkg/ipc/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/ipc.out -o $(COVERAGE_DIR)/ipc.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/ipc.out | tail -1
	@echo "$(GREEN)Coverage report: $(COVERAGE_DIR)/ipc.html$(RESET)"

.PHONY: coverage-keyboard
## coverage-keyboard: Generate keyboard package coverage report
coverage-keyboard:
	@echo "$(CYAN)Generating keyboard coverage report...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/keyboard.out -covermode=atomic ./pkg/keyboard/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/keyboard.out -o $(COVERAGE_DIR)/keyboard.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/keyboard.out | tail -1
	@echo "$(GREEN)Coverage report: $(COVERAGE_DIR)/keyboard.html$(RESET)"

.PHONY: coverage-notify
## coverage-notify: Generate notification package coverage report
coverage-notify:
	@echo "$(CYAN)Generating notification coverage report...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/notify.out -covermode=atomic ./pkg/notify/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/notify.out -o $(COVERAGE_DIR)/notify.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/notify.out | tail -1
	@echo "$(GREEN)Coverage report: $(COVERAGE_DIR)/notify.html$(RESET)"

.PHONY: coverage-staticpw
## coverage-staticpw: Generate static password coverage report
coverage-staticpw:
	@echo "$(CYAN)Generating static password coverage report...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/staticpw.out -covermode=atomic ./pkg/staticpw/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/staticpw.out -o $(COVERAGE_DIR)/staticpw.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/staticpw.out | tail -1
	@echo "$(GREEN)Coverage report: $(COVERAGE_DIR)/staticpw.html$(RESET)"

# Wildcard coverage target for any package under pkg/
.PHONY: coverage-%
coverage-%:
	@echo "$(CYAN)Generating coverage for pkg/$*...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/$*.out -covermode=atomic ./pkg/$*/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/$*.out -o $(COVERAGE_DIR)/$*-coverage.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/$*.out | tail -1
	@echo "$(GREEN)Coverage report: $(COVERAGE_DIR)/$*-coverage.html$(RESET)"

# ==============================================================================
# Lint / Format Targets
# ==============================================================================

.PHONY: fmt
## fmt: Format Go source code with gofmt
fmt:
	@echo "$(CYAN)Formatting code...$(RESET)"
	@$(GOFMT) -s -w .
	@echo "$(GREEN)Code formatted$(RESET)"

.PHONY: fmt-check
## fmt-check: Check if Go code is properly formatted
fmt-check:
	@echo "$(CYAN)Checking code formatting...$(RESET)"
	@UNFORMATTED=$$($(GOFMT) -l . 2>/dev/null | grep -v vendor | grep -v build || true); \
	if [ -n "$$UNFORMATTED" ]; then \
		echo "$(RED)Unformatted files:$(RESET)"; \
		echo "$$UNFORMATTED"; \
		exit 1; \
	fi
	@echo "$(GREEN)Code formatting check passed$(RESET)"

.PHONY: vet
## vet: Run go vet on the codebase
vet:
	@echo "$(CYAN)Running go vet...$(RESET)"
	@$(GOVET) ./...
	@echo "$(GREEN)Vet checks passed$(RESET)"

.PHONY: lint
## lint: Run golangci-lint (falls back to go vet)
lint:
	@echo "$(CYAN)$(BOLD)Running linters...$(RESET)"
	@if [ -x "$(GOLANGCI_LINT)" ]; then \
		$(GOLANGCI_LINT) run --build-tags "$(BUILD_TAGS)" ./...; \
		echo "$(GREEN)Linter checks passed$(RESET)"; \
	else \
		echo "$(YELLOW)golangci-lint not found, falling back to go vet$(RESET)"; \
		$(GOVET) ./...; \
		echo "$(GREEN)Vet checks passed$(RESET)"; \
	fi

.PHONY: lint-frontend
## lint-frontend: Run svelte-check and eslint on the frontend
lint-frontend: frontend-check
	@echo "$(CYAN)Running frontend linters...$(RESET)"
	@if cd $(FRONTEND_DIR) && npx eslint --version >/dev/null 2>&1; then \
		cd $(FRONTEND_DIR) && npx eslint src/; \
		echo "$(GREEN)Frontend ESLint checks passed$(RESET)"; \
	else \
		echo "$(YELLOW)ESLint not configured, svelte-check only$(RESET)"; \
	fi
	@echo "$(GREEN)Frontend lint complete$(RESET)"

.PHONY: lint-all
## lint-all: Run all linters (Go + frontend)
lint-all: lint lint-frontend
	@echo "$(GREEN)$(BOLD)All lint checks passed$(RESET)"

# ==============================================================================
# Dependency Targets
# ==============================================================================

.PHONY: deps
## deps: Install all dependencies (Go modules + npm packages)
deps: deps-go frontend-install
	@echo "$(GREEN)$(BOLD)All dependencies installed$(RESET)"

.PHONY: deps-go
## deps-go: Download and verify Go module dependencies
deps-go:
	@echo "$(CYAN)Installing Go dependencies...$(RESET)"
	@$(GO) mod download
	@$(GO) mod verify
	@echo "$(GREEN)Go dependencies installed$(RESET)"

.PHONY: deps-gui
## deps-gui: Install Wails CLI and frontend dependencies
deps-gui: frontend-install
	@echo "$(CYAN)Checking Wails CLI...$(RESET)"
	@if ! command -v wails >/dev/null 2>&1; then \
		echo "$(CYAN)Installing Wails CLI...$(RESET)"; \
		$(GO) install github.com/wailsapp/wails/v2/cmd/wails@latest; \
		echo "$(GREEN)Wails CLI installed$(RESET)"; \
	else \
		echo "$(GREEN)Wails CLI already installed: $$(wails version 2>/dev/null || echo 'unknown')$(RESET)"; \
	fi
	@echo "$(GREEN)GUI dependencies ready$(RESET)"

# ==============================================================================
# Clean Targets
# ==============================================================================

.PHONY: clean
## clean: Remove all build artifacts and test outputs
clean:
	@echo "$(CYAN)$(BOLD)Cleaning build artifacts...$(RESET)"
	@$(GOCLEAN)
	@rm -rf $(BUILD_DIR)
	@rm -f *.out *.log *.test *.prof
	@rm -f xkey xkey-gui
	@echo "$(GREEN)Clean complete$(RESET)"

.PHONY: clean-frontend
## clean-frontend: Remove node_modules and frontend build output
clean-frontend:
	@echo "$(CYAN)Cleaning frontend artifacts...$(RESET)"
	@rm -rf $(FRONTEND_DIR)/node_modules
	@rm -rf $(FRONTEND_DIR)/dist
	@echo "$(GREEN)Frontend clean complete$(RESET)"

.PHONY: clean-all
## clean-all: Remove all build artifacts including frontend
clean-all: clean clean-frontend
	@echo "$(GREEN)$(BOLD)Full clean complete$(RESET)"

# ==============================================================================
# Benchmark Targets
# ==============================================================================

.PHONY: bench-gui
## bench-gui: Run GUI service benchmarks
bench-gui:
	@echo "$(CYAN)$(BOLD)Running GUI benchmarks...$(RESET)"
	@mkdir -p $(BUILD_DIR)/bench
	@$(GO) test -tags "$(BUILD_TAGS)" -bench=. -benchmem -run=^$$ ./pkg/gui/... | tee $(BUILD_DIR)/bench/gui.txt
	@echo "$(GREEN)Benchmarks complete: $(BUILD_DIR)/bench/gui.txt$(RESET)"

.PHONY: bench-authenticator
## bench-authenticator: Run authenticator benchmarks
bench-authenticator:
	@echo "$(CYAN)$(BOLD)Running authenticator benchmarks...$(RESET)"
	@mkdir -p $(BUILD_DIR)/bench
	@$(GO) test -tags "$(BUILD_TAGS)" -bench=. -benchmem -run=^$$ ./pkg/authenticator/... | tee $(BUILD_DIR)/bench/authenticator.txt
	@echo "$(GREEN)Benchmarks complete: $(BUILD_DIR)/bench/authenticator.txt$(RESET)"

# Wildcard benchmark target for any package under pkg/
.PHONY: bench-%
bench-%:
	@echo "$(CYAN)$(BOLD)Running benchmarks for pkg/$*...$(RESET)"
	@mkdir -p $(BUILD_DIR)/bench
	@$(GO) test -tags "$(BUILD_TAGS)" -bench=. -benchmem -run=^$$ ./pkg/$*/... | tee $(BUILD_DIR)/bench/$*.txt
	@echo "$(GREEN)Benchmarks complete: $(BUILD_DIR)/bench/$*.txt$(RESET)"

# Wildcard test target for any package under pkg/
.PHONY: test-%
test-%:
	@echo "$(CYAN)Running tests for pkg/$*...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/$*/...
	@echo "$(GREEN)Tests passed for pkg/$*$(RESET)"

# ==============================================================================
# Docker E2E Targets
# ==============================================================================

.PHONY: playwright-test-docker
## playwright-test-docker: Run Playwright GUI tests in Docker with swtpm and headless browser
playwright-test-docker:
	@echo "$(CYAN)$(BOLD)Building Playwright test container...$(RESET)"
	@cd test/e2e && docker compose build
	@echo "$(CYAN)$(BOLD)Running Playwright GUI tests with swtpm...$(RESET)"
	@cd test/e2e && docker compose run --rm e2e
	@echo "$(GREEN)Playwright tests passed$(RESET)"

.PHONY: playwright-test-piv
## playwright-test-piv: Playwright PIV integration tests
playwright-test-piv:
	@echo "$(CYAN)$(BOLD)Running Playwright PIV tests...$(RESET)"
	@cd $(FRONTEND_DIR) && npx playwright test piv-integration
	@echo "$(GREEN)Playwright PIV tests passed$(RESET)"

.PHONY: test-fido2-pkcs11
## test-fido2-pkcs11: FIDO2 PKCS#11 composite key backend unit tests
test-fido2-pkcs11:
	@echo "$(CYAN)$(BOLD)Running FIDO2 PKCS#11 composite backend tests...$(RESET)"
	@go test -v -tags "pkcs11,fido2,webauthn" -count=1 -timeout 60s -run 'TestComposite.*PKCS11' ./pkg/authenticator/keybackend/...
	@echo "$(GREEN)FIDO2 PKCS#11 composite backend tests passed$(RESET)"

.PHONY: integration-test-fido2-adapter
## integration-test-fido2-adapter: FIDO2 adapter integration tests with ALL backends (software + TPM2 + PKCS#11)
integration-test-fido2-adapter:
	@echo "$(CYAN)$(BOLD)Setting up SoftHSM PIV test certificates...$(RESET)"
	@bash test/e2e/setup-softhsm-piv.sh
	@echo "$(CYAN)$(BOLD)Running FIDO2 adapter integration tests (software + TPM2 + PKCS#11)...$(RESET)"
	@go test -v -tags "pkcs11,fido2,webauthn,integration" -count=1 -timeout 120s -run 'TestAllBackends' ./pkg/authenticator/keybackend/...
	@echo "$(GREEN)FIDO2 adapter integration tests passed (all backends)$(RESET)"

.PHONY: integration-test-piv-pkcs11
## integration-test-piv-pkcs11: PIV PKCS#11 certificate loading integration tests (requires SoftHSM)
integration-test-piv-pkcs11:
	@echo "$(CYAN)$(BOLD)Setting up SoftHSM PIV test certificates...$(RESET)"
	@bash test/e2e/setup-softhsm-piv.sh
	@echo "$(CYAN)$(BOLD)Running PKCS#11 PIV integration tests with SoftHSM...$(RESET)"
	@cd .. && go test -v -tags "pkcs11,integration" -count=1 -timeout 120s -run 'TestSoftHSM' ./pkg/pivcert/pkcs11/...
	@echo "$(GREEN)PKCS#11 PIV integration tests passed$(RESET)"

.PHONY: integration-test-pkcs11
## integration-test-pkcs11: Run all PKCS#11 integration tests (FIDO2 adapter + PIV certs)
integration-test-pkcs11: integration-test-fido2-adapter integration-test-piv-pkcs11
	@echo "$(GREEN)$(BOLD)All PKCS#11 integration tests passed$(RESET)"

.PHONY: integration-test-fido2-hardware
## integration-test-fido2-hardware: Run FIDO2 backend adapter tests against real swtpm + SoftHSM2 in Docker
integration-test-fido2-hardware:
	@echo "$(CYAN)$(BOLD)Building FIDO2 hardware-backend test container...$(RESET)"
	@cd test/integration && docker compose -f docker-compose.fido2-hardware.yml build
	@echo "$(CYAN)$(BOLD)Running FIDO2 adapter tests against real swtpm + SoftHSM2...$(RESET)"
	@cd test/integration && docker compose -f docker-compose.fido2-hardware.yml run --rm fido2-hardware-test
	@echo "$(GREEN)$(BOLD)FIDO2 hardware-backend tests passed$(RESET)"

.PHONY: playwright-test-shell
## playwright-test-shell: Open a shell in the Playwright test container for debugging
playwright-test-shell:
	@cd test/e2e && docker compose run --rm --entrypoint bash e2e

# ==============================================================================
# Skill Generation Targets
# ==============================================================================

SKILL_REFERENCE := skills/xkey-agent/reference/cli.md
SKILLGEN_TAGS   := ble codec_json

.PHONY: skill-reference
## skill-reference: Regenerate the agent skill's complete CLI reference from the cobra command tree
skill-reference:
	@mkdir -p $(dir $(SKILL_REFERENCE))
	@GOWORK=off $(GO) run -tags '$(SKILLGEN_TAGS)' ./tools/skillgen > $(SKILL_REFERENCE)
	@echo "$(GREEN)✓ $(SKILL_REFERENCE) regenerated$(RESET)"

.PHONY: check-skill-reference
## check-skill-reference: Fail when the CLI reference is stale or SKILL.md cites a nonexistent command/flag
check-skill-reference:
	@tmp=$$(mktemp); \
	GOWORK=off $(GO) run -tags '$(SKILLGEN_TAGS)' ./tools/skillgen > "$$tmp" || { rm -f "$$tmp"; exit 1; }; \
	if ! diff -u $(SKILL_REFERENCE) "$$tmp" >/dev/null; then \
		rm -f "$$tmp"; \
		echo "$(RED)✗ $(SKILL_REFERENCE) is stale: run 'make skill-reference'$(RESET)"; \
		exit 1; \
	fi; \
	rm -f "$$tmp"; \
	GOWORK=off $(GO) run -tags '$(SKILLGEN_TAGS)' ./tools/skillgen -check skills/xkey-agent/SKILL.md || { echo "$(RED)✗ SKILL.md cites a command or flag xkey does not have$(RESET)"; exit 1; }; \
	echo "$(GREEN)✓ skill reference is current and SKILL.md matches the command tree$(RESET)"

# ==============================================================================
# Help Target
# ==============================================================================

.PHONY: help
## help: Display this help message
help:
	@echo "$(BOLD)$(BLUE)xKey Desktop GUI Makefile$(RESET)"
	@echo "$(CYAN)Wails v2 desktop application with Svelte 4 + TypeScript + TailwindCSS$(RESET)"
	@echo ""
	@echo "$(BOLD)Version: $(VERSION)$(RESET)"
	@echo ""
	@echo "$(BOLD)Usage:$(RESET)"
	@echo "  make $(YELLOW)<target>$(RESET)"
	@echo ""
	@echo "$(BOLD)Build Targets:$(RESET)"
	@grep -E '^## (build|dev-gui)' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ": "}; {printf "  $(YELLOW)%-28s$(RESET) %s\n", $$1, $$2}' | \
		sed 's/^## //'
	@echo ""
	@echo "$(BOLD)Frontend Targets:$(RESET)"
	@grep -E '^## frontend' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ": "}; {printf "  $(YELLOW)%-28s$(RESET) %s\n", $$1, $$2}' | \
		sed 's/^## //'
	@echo ""
	@echo "$(BOLD)Test Targets:$(RESET)"
	@grep -E '^## (test|integration)' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ": "}; {printf "  $(YELLOW)%-28s$(RESET) %s\n", $$1, $$2}' | \
		sed 's/^## //'
	@echo ""
	@echo "$(BOLD)Coverage Targets:$(RESET)"
	@grep -E '^## coverage' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ": "}; {printf "  $(YELLOW)%-28s$(RESET) %s\n", $$1, $$2}' | \
		sed 's/^## //'
	@echo ""
	@echo "$(BOLD)Lint / Format Targets:$(RESET)"
	@grep -E '^## (lint|fmt|vet)' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ": "}; {printf "  $(YELLOW)%-28s$(RESET) %s\n", $$1, $$2}' | \
		sed 's/^## //'
	@echo ""
	@echo "$(BOLD)Dependency Targets:$(RESET)"
	@grep -E '^## deps' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ": "}; {printf "  $(YELLOW)%-28s$(RESET) %s\n", $$1, $$2}' | \
		sed 's/^## //'
	@echo ""
	@echo "$(BOLD)Clean Targets:$(RESET)"
	@grep -E '^## clean' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ": "}; {printf "  $(YELLOW)%-28s$(RESET) %s\n", $$1, $$2}' | \
		sed 's/^## //'
	@echo ""
	@echo "$(BOLD)Benchmark Targets:$(RESET)"
	@grep -E '^## bench' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ": "}; {printf "  $(YELLOW)%-28s$(RESET) %s\n", $$1, $$2}' | \
		sed 's/^## //'
	@echo ""
	@echo "$(BOLD)Docker E2E Targets:$(RESET)"
	@grep -E '^## test-e2e-docker' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ": "}; {printf "  $(YELLOW)%-28s$(RESET) %s\n", $$1, $$2}' | \
		sed 's/^## //'
	@echo ""
	@echo "$(BOLD)Wildcard Targets:$(RESET)"
	@echo "  $(YELLOW)test-<package>$(RESET)              Run tests for pkg/<package>/..."
	@echo "  $(YELLOW)coverage-<package>$(RESET)          Generate coverage for pkg/<package>/..."
	@echo "  $(YELLOW)bench-<package>$(RESET)             Run benchmarks for pkg/<package>/..."
	@echo ""
	@echo "$(BOLD)Examples:$(RESET)"
	@echo "  make build                    Build CLI and GUI binaries"
	@echo "  make dev-gui                  Start Wails dev mode with hot reload"
	@echo "  make test                     Run all unit tests"
	@echo "  make test-authenticator       Run authenticator package tests"
	@echo "  make coverage-gui             Generate GUI coverage report"
	@echo "  make lint-all                 Run Go and frontend linters"
	@echo "  make deps                     Install Go and npm dependencies"
	@echo "  make clean-all                Remove all artifacts including node_modules"
