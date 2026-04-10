# Makefile for go-xkms
# Secure key management library with native and shared object support

# ==============================================================================
# Configuration
# ==============================================================================

# Version management
VERSION := $(shell cat VERSION 2>/dev/null || echo "0.0.1-alpha")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -X github.com/jeremyhahn/go-xkms/pkg/cli.Version=$(VERSION) \
           -X github.com/jeremyhahn/go-xkms/pkg/cli.GitCommit=$(GIT_COMMIT) \
           -X github.com/jeremyhahn/go-xkms/pkg/cli.BuildDate=$(BUILD_DATE)

# Optional backend features (set to 1 to enable)
# Default: Software backends enabled, hardware/cloud backends disabled
WITH_PKCS8 ?= 1
WITH_TPM2 ?= 0
WITH_AWS_KMS ?= 0
WITH_GCP_KMS ?= 0
WITH_AZURE_KV ?= 0
WITH_VAULT ?= 0
WITH_PKCS11 ?= 0

# Quantum-safe cryptography (ML-DSA, ML-KEM) is always enabled.
# Uses pure-Go implementations (circl, crypto/mlkem). No external libraries required.

# FROST threshold signatures support (RFC 9591)
# Default: Enabled - FROST threshold signatures compiled in by default
WITH_FROST ?= 1

# Group variables (convenience flags to enable all backends for a provider)
# Setting these will override individual backend flags
WITH_AWS ?= 0
WITH_GCP ?= 0
WITH_AZURE ?= 0

# Apply group flags
ifeq ($(WITH_AWS),1)
	WITH_AWS_KMS := 1
endif
ifeq ($(WITH_GCP),1)
	WITH_GCP_KMS := 1
endif
ifeq ($(WITH_AZURE),1)
	WITH_AZURE_KV := 1
endif


# All available build tags for release builds
# CLI doesn't include pkcs11 (requires CGO) for easier distribution
CLI_BUILD_TAGS := pkcs8 awskms gcpkms azurekv vault frost codec_cbor codec_json codec_msgpack
# Server includes all tags including pkcs11
SERVER_BUILD_TAGS := pkcs8 awskms gcpkms azurekv vault pkcs11 frost codec_cbor codec_json codec_msgpack
# All tags for integration testing (includes all possible build tags)
ALL_TAGS := integration frost pkcs8 pkcs11 awskms gcpkms azurekv vault nitrokey fido2 webauthn codec_cbor codec_json codec_msgpack

# Build tags based on backend flags (for development/testing)
# Codec tags are always required for go-qrdb DAO layer serialization
BUILD_TAGS := codec_cbor codec_json codec_msgpack
ifeq ($(WITH_PKCS8),1)
	BUILD_TAGS += pkcs8
endif
ifeq ($(WITH_TPM_SIMULATOR),1)
	BUILD_TAGS += 
endif
ifeq ($(WITH_AWS_KMS),1)
	BUILD_TAGS += awskms
endif
ifeq ($(WITH_GCP_KMS),1)
	BUILD_TAGS += gcpkms
endif
ifeq ($(WITH_AZURE_KV),1)
	BUILD_TAGS += azurekv
endif
ifeq ($(WITH_VAULT),1)
	BUILD_TAGS += vault
endif
ifeq ($(WITH_PKCS11),1)
	BUILD_TAGS += pkcs11
endif
ifeq ($(WITH_FROST),1)
	BUILD_TAGS += frost
endif


# Build tag flags for go commands
ifneq ($(BUILD_TAGS),)
	TAG_FLAGS := -tags "$(BUILD_TAGS)"
else
	TAG_FLAGS :=
endif

# Go parameters
GO := go
GOBUILD := $(GO) build -buildvcs=false $(TAG_FLAGS) -ldflags "$(LDFLAGS)"
GOCLEAN := $(GO) clean
GOTEST := $(GO) test $(TAG_FLAGS)
GOGET := $(GO) get
GOMOD := $(GO) mod
GOVET := $(GO) vet $(TAG_FLAGS)
GOFMT := gofmt

# Project structure
PROJECT_NAME := go-xkms
MODULE := github.com/jeremyhahn/go-xkms
PKG_DIR := ./pkg/...
CMD_DIR := ./cmd/...
TEST_DIR := ./test/...
INTEGRATION_TEST_DIR := .
API_TEST_DIR := $(CURDIR)/test/integration/api

# Build artifacts
BUILD_DIR := build
LIB_DIR := $(BUILD_DIR)/lib
BIN_DIR := $(BUILD_DIR)/bin
COVERAGE_DIR := $(BUILD_DIR)/coverage
SHARED_LIB := $(LIB_DIR)/libxkms-$(VERSION).so
SHARED_LIB_LINK := $(LIB_DIR)/libxkms.so
CGO_SOURCE := ./cmd/cgo

# Docker configuration
DOCKER_IMAGE := $(PROJECT_NAME):latest
DOCKER_INTEGRATION_IMAGE := $(PROJECT_NAME)-integration:latest
DOCKER_CONTAINER := $(PROJECT_NAME)-container
BUILDER_IMAGE := $(PROJECT_NAME)-builder:latest
XKEY_BUILDER_IMAGE := $(PROJECT_NAME)-xkey-builder:latest

# Sibling module mounts (for go.mod replace directives referencing ../go-qrdb, ../go-quicraft)
PARENT_DIR := $(dir $(CURDIR))
SIBLING_MOUNTS := -v $(PARENT_DIR)go-qrdb:/go-qrdb:cached \
                  -v $(PARENT_DIR)go-quicraft:/go-quicraft:cached

# ==============================================================================
# PKCS#11 Module Configuration
# ==============================================================================

# PKCS#11 module paths
PKCS11_MODULE_SO := $(LIB_DIR)/libxkms_pkcs11.so
PKCS11_MODULE_HEADER := $(LIB_DIR)/libxkms_pkcs11.h

# PKCS#11 test configuration
PKCS11_TOKEN_LABEL ?= xkms-token
PKCS11_PIN ?= 87654321
PKCS11_SO_PIN ?= 12345678

# Multi-protocol connection configuration
# Unix socket (gRPC over UDS)
XKMS_UNIX_SOCKET ?= /var/run/xkms/xkms.sock
# TCP (gRPC over TCP)
XKMS_GRPC_ADDR ?= localhost:9443
# Container gRPC address (for tests running inside devcontainer network)
XKMS_GRPC_ADDR_CONTAINER ?= xkms-server:9443
# PKCS#11 module path inside container
PKCS11_MODULE_CONTAINER := /workspace/build/lib/libxkms_pkcs11.so
XKMS_GRPC_TLS_ENABLED ?= false
XKMS_GRPC_TLS_INSECURE ?= true

# Test timeout
PKCS11_TEST_TIMEOUT ?= 10m

# Test configuration - include codec build tags for go-codec support
TEST_FLAGS := -v -race -tags="codec_cbor codec_json codec_msgpack tpm_simulator"
COVERAGE_FILE := $(COVERAGE_DIR)/coverage.out
COVERAGE_HTML := $(COVERAGE_DIR)/coverage.html
COVERAGE_THRESHOLD := 80
# Integration test tags include both backend tags and integration tag
ifneq ($(BUILD_TAGS),)
	INTEGRATION_TEST_FLAGS := -v -tags="integration pkcs8 pkcs11 codec_cbor codec_json codec_msgpack $(BUILD_TAGS)"
else
	INTEGRATION_TEST_FLAGS := -v -tags="integration pkcs8 pkcs11 codec_cbor codec_json codec_msgpack"
endif

# Color output (ANSI escape codes)
RESET := $(shell printf '\033[0m')
BOLD := $(shell printf '\033[1m')
RED := $(shell printf '\033[31m')
GREEN := $(shell printf '\033[32m')
YELLOW := $(shell printf '\033[33m')
BLUE := $(shell printf '\033[34m')
CYAN := $(shell printf '\033[36m')

# ==============================================================================
# Default Target
# ==============================================================================

.DEFAULT_GOAL := build

# ==============================================================================
# Primary Targets
# ==============================================================================

.PHONY: all
## all: Build everything (library, shared object, run tests)
all: clean deps fmt vet build test
	@echo "$(GREEN)$(BOLD)✓ Build complete!$(RESET)"

.PHONY: deps
## deps: Install dependencies for tests (SoftHSM, SWTPM utilities)
deps:
	@echo "$(CYAN)$(BOLD)→ Installing dependencies...$(RESET)"
	@$(GOMOD) download
	@$(GOMOD) verify
	@echo "$(GREEN)✓ Go dependencies installed$(RESET)"
	@echo "$(YELLOW)Note: For integration tests, ensure SoftHSM and SWTPM are installed:$(RESET)"
	@echo "  - Ubuntu/Debian: sudo apt-get install softhsm2 swtpm swtpm-tools"
	@echo "  - macOS: brew install softhsm swtpm"

.PHONY: build
## build: Build the shared library, CLI, server binaries, and xkey (default)
build: lib build-cli build-servers build-xkey

.PHONY: build-local
## build-local: Build everything locally without Docker (requires dev packages)
build-local: lib build-cli build-xkey-local

.PHONY: builder-image
## builder-image: Build the Docker builder image for CGO builds (lib, server)
builder-image:
	@echo "$(CYAN)$(BOLD)→ Building builder image...$(RESET)"
	@DOCKER_BUILDKIT=0 docker build -t $(BUILDER_IMAGE) -f Dockerfile.builder . >/dev/null 2>&1

.PHONY: build-cli
## build-cli: Build the xkmsctl CLI binary (pure Go, no CGO)
build-cli:
	@echo "$(CYAN)$(BOLD)→ Building xkmsctl CLI...$(RESET)"
	@mkdir -p $(BIN_DIR)
	@CGO_ENABLED=0 $(GOBUILD) -o $(BIN_DIR)/xkmsctl ./cmd/xkmsctl
	@echo "$(GREEN)✓ CLI binary built: $(BIN_DIR)/xkmsctl$(RESET)"

.PHONY: build-server
## build-server: Build the unified xkmsd server binary (uses Docker for CGO deps)
build-server: builder-image
	@echo "$(CYAN)$(BOLD)→ Building unified xkmsd server...$(RESET)"
	@mkdir -p $(BIN_DIR)
	@docker run --rm \
		-v $(CURDIR):/workspace:cached \
		$(SIBLING_MOUNTS) \
		-w /workspace \
		$(BUILDER_IMAGE) \
		bash -c "CGO_ENABLED=1 go build -buildvcs=false -tags '$(BUILD_TAGS)' -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/xkmsd ./cmd/xkmsd/"
	@echo "$(GREEN)✓ Unified server binary built: $(BIN_DIR)/xkmsd$(RESET)"

.PHONY: build-servers
## build-servers: Build server binary (alias for build-server)
build-servers: build-server
	@echo "$(GREEN)$(BOLD)✓ Server binary built successfully!$(RESET)"

.PHONY: build-xkey
## build-xkey: Build the xkey binary with embedded GUI frontend (uses Docker)
## Uses the xkey builder image with SIBLING_MOUNTS to resolve symlinked siblings.
## The binary is output to $(BIN_DIR)/xkey alongside other project binaries.
build-xkey:
	@echo "$(CYAN)$(BOLD)→ Building xkey builder image...$(RESET)"
	@DOCKER_BUILDKIT=0 docker build -t $(XKEY_BUILDER_IMAGE) -f xkey/Dockerfile.builder xkey/ >/dev/null 2>&1
	@echo "$(CYAN)$(BOLD)→ Building xkey frontend...$(RESET)"
	@docker run --rm \
		-v $(CURDIR):/workspace:cached \
		-w /workspace/xkey/frontend \
		$(XKEY_BUILDER_IMAGE) \
		bash -c "npm install --silent && node ./node_modules/vite/bin/vite.js build && chown -R $(shell id -u):$(shell id -g) dist/ node_modules/"
	@echo "$(CYAN)$(BOLD)→ Building xkey browser extension...$(RESET)"
	@docker run --rm \
		-v $(CURDIR):/workspace:cached \
		-w /workspace/xkey/extension \
		$(XKEY_BUILDER_IMAGE) \
		bash -c "set -e && rm -rf node_modules && npm install --silent && node node_modules/typescript/lib/tsc.js && cp manifest.json dist/ && cp src/popup.html dist/ && mkdir -p dist/icons && (cp -r src/icons/* dist/icons/ 2>/dev/null || true) && chown -R $(shell id -u):$(shell id -g) dist/ node_modules/"
	@echo "$(CYAN)$(BOLD)→ Building xkey binary...$(RESET)"
	@mkdir -p $(BIN_DIR)
	@docker run --rm \
		-v $(CURDIR):/workspace:cached \
		$(SIBLING_MOUNTS) \
		-w /workspace/xkey \
		$(XKEY_BUILDER_IMAGE) \
		bash -c "CGO_ENABLED=1 go build -tags 'ble,production,codec_json,pkcs11,webkit2_41' -buildvcs=false -ldflags '-X github.com/jeremyhahn/go-xkms/xkey/cmd/xkey/cmd.Version=$(VERSION) -X github.com/jeremyhahn/go-xkms/xkey/cmd/xkey/cmd.Commit=$(GIT_COMMIT) -X github.com/jeremyhahn/go-xkms/xkey/cmd/xkey/cmd.Date=$(BUILD_DATE)' -o /workspace/$(BIN_DIR)/xkey ./cmd/xkey && chown $(shell id -u):$(shell id -g) /workspace/$(BIN_DIR)/xkey"
	@echo "$(GREEN)✓ xkey binary built: $(BIN_DIR)/xkey$(RESET)"
	@echo "$(GREEN)  GUI mode:  ./$(BIN_DIR)/xkey$(RESET)"
	@echo "$(GREEN)  CLI mode:  ./$(BIN_DIR)/xkey --no-gui$(RESET)"

.PHONY: build-xkey-local
## build-xkey-local: Build xkey locally without Docker (requires dev packages)
## Delegates to xkey/Makefile and copies the binary to $(BIN_DIR)/xkey.
build-xkey-local:
	@$(MAKE) -C xkey build-local
	@mkdir -p $(BIN_DIR)
	@cp xkey/build/bin/xkey $(BIN_DIR)/xkey
	@echo "$(GREEN)✓ xkey binary copied to: $(BIN_DIR)/xkey$(RESET)"

# ==============================================================================
# PKCS#11 Module Targets
# ==============================================================================

.PHONY: build-pkcs11-module
## build-pkcs11-module: Build the PKCS#11 shared library (libxkms_pkcs11.so)
build-pkcs11-module:
	@echo "$(CYAN)$(BOLD)→ Building PKCS#11 shared library...$(RESET)"
	@mkdir -p $(LIB_DIR)
	@CGO_ENABLED=1 $(GO) build -buildmode=c-shared \
		-o $(LIB_DIR)/libxkms_pkcs11.so \
		./cmd/pkcs11-module
	@echo "$(GREEN)✓ PKCS#11 module built: $(LIB_DIR)/libxkms_pkcs11.so$(RESET)"

.PHONY: test-pkcs11-module
## test-pkcs11-module: Run PKCS#11 module unit tests
test-pkcs11-module:
	@echo "$(CYAN)→ Testing PKCS#11 module package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/pkcs11/module/...
	@echo "$(GREEN)✓ PKCS#11 module tests passed$(RESET)"

.PHONY: coverage-pkcs11-module
## coverage-pkcs11-module: Generate PKCS#11 module coverage report
coverage-pkcs11-module:
	@echo "$(CYAN)→ Generating PKCS#11 module coverage report...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/pkcs11_module.out -covermode=atomic ./pkg/pkcs11/module/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/pkcs11_module.out -o $(COVERAGE_DIR)/pkcs11_module.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/pkcs11_module.out | tail -1
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/pkcs11_module.html$(RESET)"

.PHONY: bench-pkcs11-module
## bench-pkcs11-module: Run PKCS#11 module benchmarks
bench-pkcs11-module:
	@echo "$(CYAN)$(BOLD)→ Running PKCS#11 module benchmarks...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=. -benchmem -run=^$$ ./pkg/pkcs11/module/... | tee $(BENCH_DIR)/pkcs11-module.txt
	@echo "$(GREEN)✓ PKCS#11 module benchmarks complete$(RESET)"
	@echo "$(CYAN)Results saved to: $(BENCH_DIR)/pkcs11-module.txt$(RESET)"

.PHONY: bench-staticpw
## bench-staticpw: Run static password benchmarks
bench-staticpw:
	@echo "$(CYAN)→ Running static password benchmarks...$(RESET)"
	@cd xkey && $(GOTEST) -bench=. -benchmem ./pkg/staticpw/...

.PHONY: test-pkcs11-compat
## test-pkcs11-compat: Test PKCS#11 module compatibility with pkcs11-tool
test-pkcs11-compat: build-pkcs11-module
	@echo "$(CYAN)$(BOLD)→ Testing PKCS#11 compatibility with pkcs11-tool...$(RESET)"
	@if command -v pkcs11-tool >/dev/null 2>&1; then \
		echo "$(CYAN)→ Listing slots...$(RESET)"; \
		pkcs11-tool --module $(LIB_DIR)/libxkms_pkcs11.so --list-slots || true; \
		echo "$(CYAN)→ Listing mechanisms...$(RESET)"; \
		pkcs11-tool --module $(LIB_DIR)/libxkms_pkcs11.so --list-mechanisms || true; \
		echo "$(GREEN)✓ Compatibility test complete$(RESET)"; \
	else \
		echo "$(YELLOW)⚠ pkcs11-tool not found. Install opensc to run compatibility tests.$(RESET)"; \
	fi

.PHONY: test-uhid
## test-uhid: Run UHID package unit tests
test-uhid:
	@echo "$(CYAN)→ Testing UHID package...$(RESET)"
	@cd xkey && $(GOTEST) $(TEST_FLAGS) ./pkg/uhid/...

.PHONY: test-xkey
## test-xkey: Run xkey command unit tests
test-xkey:
	@echo "$(CYAN)→ Testing xkey command...$(RESET)"
	@cd xkey && $(GOTEST) $(TEST_FLAGS) ./cmd/xkey/...

.PHONY: test-staticpw
## test-staticpw: Run static password unit tests
test-staticpw:
	@echo "$(CYAN)→ Testing static password...$(RESET)"
	@cd xkey && $(GOTEST) $(TEST_FLAGS) ./pkg/staticpw/...

.PHONY: test-webauthn-verification
## test-webauthn-verification: Run WebAuthn end-to-end verification tests (MakeCredential → GetAssertion → RP verify)
test-webauthn-verification:
	@echo "$(CYAN)→ Testing WebAuthn verification flow...$(RESET)"
	@cd xkey && $(GOTEST) $(TEST_FLAGS) -run TestWebAuthnVerification ./pkg/authenticator/...

.PHONY: coverage-uhid
## coverage-uhid: Generate UHID package coverage report
coverage-uhid:
	@echo "$(CYAN)→ Generating UHID coverage report...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@cd xkey && $(GOTEST) -race -coverprofile=../$(COVERAGE_DIR)/uhid.out -covermode=atomic ./pkg/uhid/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/uhid.out -o $(COVERAGE_DIR)/uhid.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/uhid.out | tail -1
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/uhid.html$(RESET)"

.PHONY: coverage-xkey-cmd
## coverage-xkey-cmd: Generate xkey command coverage report
coverage-xkey-cmd:
	@echo "$(CYAN)→ Generating xkey command coverage report...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@cd xkey && $(GOTEST) -race -coverprofile=../$(COVERAGE_DIR)/xkey-cmd.out -covermode=atomic ./cmd/xkey/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/xkey-cmd.out -o $(COVERAGE_DIR)/xkey-cmd.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/xkey-cmd.out | tail -1
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/xkey-cmd.html$(RESET)"

.PHONY: coverage-staticpw
## coverage-staticpw: Generate static password coverage report
coverage-staticpw:
	@echo "$(CYAN)→ Generating static password coverage report...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@cd xkey && $(GOTEST) -race -coverprofile=../$(COVERAGE_DIR)/staticpw.out -covermode=atomic ./pkg/staticpw/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/staticpw.out -o $(COVERAGE_DIR)/staticpw.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/staticpw.out | tail -1
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/staticpw.html$(RESET)"

.PHONY: test-notify
## test-notify: Run xkey notification package unit tests
test-notify:
	@echo "$(CYAN)→ Testing notification package...$(RESET)"
	@cd xkey && $(GOTEST) $(TEST_FLAGS) ./pkg/notify/...

.PHONY: coverage-notify
## coverage-notify: Generate xkey notification package coverage report
coverage-notify:
	@echo "$(CYAN)→ Generating notification coverage report...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@cd xkey && $(GOTEST) -race -coverprofile=../$(COVERAGE_DIR)/notify.out -covermode=atomic ./pkg/notify/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/notify.out -o $(COVERAGE_DIR)/notify.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/notify.out | tail -1
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/notify.html$(RESET)"

.PHONY: test-keyboard
## test-keyboard: Run xkey keyboard package unit tests
test-keyboard:
	@echo "$(CYAN)→ Testing keyboard package...$(RESET)"
	@cd xkey && $(GOTEST) $(TEST_FLAGS) ./pkg/keyboard/...

.PHONY: coverage-keyboard
## coverage-keyboard: Generate xkey keyboard package coverage report
coverage-keyboard:
	@echo "$(CYAN)→ Generating keyboard coverage report...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@cd xkey && $(GOTEST) -race -coverprofile=../$(COVERAGE_DIR)/keyboard.out -covermode=atomic ./pkg/keyboard/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/keyboard.out -o $(COVERAGE_DIR)/keyboard.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/keyboard.out | tail -1
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/keyboard.html$(RESET)"

.PHONY: test-ipc
## test-ipc: Run xkey IPC package unit tests
test-ipc:
	@echo "$(CYAN)→ Testing IPC package...$(RESET)"
	@cd xkey && $(GOTEST) $(TEST_FLAGS) ./pkg/ipc/...

.PHONY: coverage-ipc
## coverage-ipc: Generate xkey IPC package coverage report
coverage-ipc:
	@echo "$(CYAN)→ Generating IPC coverage report...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@cd xkey && $(GOTEST) -race -coverprofile=../$(COVERAGE_DIR)/ipc.out -covermode=atomic ./pkg/ipc/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/ipc.out -o $(COVERAGE_DIR)/ipc.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/ipc.out | tail -1
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/ipc.html$(RESET)"

# ==============================================================================
# Cross-Compilation Targets (Release Builds with ALL Tags)
# ==============================================================================

.PHONY: release-binaries
## release-binaries: Build release binaries for all platforms with ALL build tags enabled
release-binaries: release-cli release-server
	@echo "$(GREEN)$(BOLD)✓ All release binaries built successfully!$(RESET)"

.PHONY: release-cli
## release-cli: Build xkmsctl for all platforms with ALL build tags
release-cli:
	@echo "$(CYAN)$(BOLD)→ Building xkmsctl for all platforms (CGO-free)...$(RESET)"
	@mkdir -p $(BIN_DIR)/release
	@echo "$(CYAN)  Building linux/amd64...$(RESET)"
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -tags ble -buildvcs=false -tags="$(CLI_BUILD_TAGS)" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsctl-linux-amd64 ./cmd/xkmsctl
	@echo "$(CYAN)  Building linux/arm64...$(RESET)"
	@GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build -tags ble -buildvcs=false -tags="$(CLI_BUILD_TAGS)" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsctl-linux-arm64 ./cmd/xkmsctl
	@echo "$(CYAN)  Building darwin/amd64...$(RESET)"
	@GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 $(GO) build -tags ble -buildvcs=false -tags="$(CLI_BUILD_TAGS)" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsctl-darwin-amd64 ./cmd/xkmsctl
	@echo "$(CYAN)  Building darwin/arm64...$(RESET)"
	@GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GO) build -tags ble -buildvcs=false -tags="$(CLI_BUILD_TAGS)" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsctl-darwin-arm64 ./cmd/xkmsctl
	@echo "$(CYAN)  Building windows/amd64...$(RESET)"
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -tags ble -buildvcs=false -tags="$(CLI_BUILD_TAGS)" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsctl-windows-amd64.exe ./cmd/xkmsctl
	@echo "$(CYAN)  Building windows/arm64...$(RESET)"
	@GOOS=windows GOARCH=arm64 CGO_ENABLED=0 $(GO) build -tags ble -buildvcs=false -tags="$(CLI_BUILD_TAGS)" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsctl-windows-arm64.exe ./cmd/xkmsctl
	@echo "$(GREEN)✓ xkmsctl binaries built for all platforms$(RESET)"

.PHONY: release-server
## release-server: Build xkmsd for all platforms with ALL build tags (including pkcs11)
release-server:
	@echo "$(CYAN)$(BOLD)→ Building xkmsd for all platforms (with all tags including pkcs11)...$(RESET)"
	@mkdir -p $(BIN_DIR)/release
	@echo "$(CYAN)  Building linux/amd64...$(RESET)"
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=1 $(GO) build -buildvcs=false -tags="$(SERVER_BUILD_TAGS)" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsd-linux-amd64 ./cmd/xkmsd/
	@echo "$(CYAN)  Building linux/arm64...$(RESET)"
	@GOOS=linux GOARCH=arm64 CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc $(GO) build -buildvcs=false -tags="$(SERVER_BUILD_TAGS)" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsd-linux-arm64 ./cmd/xkmsd/ || echo "$(YELLOW)⚠ Cross-compilation for linux/arm64 requires aarch64-linux-gnu-gcc$(RESET)"
	@echo "$(CYAN)  Building darwin/amd64...$(RESET)"
	@GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 $(GO) build -buildvcs=false -tags="$(SERVER_BUILD_TAGS)" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsd-darwin-amd64 ./cmd/xkmsd/ || echo "$(YELLOW)⚠ Cross-compilation for darwin/amd64 may require macOS SDK$(RESET)"
	@echo "$(CYAN)  Building darwin/arm64...$(RESET)"
	@GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 $(GO) build -buildvcs=false -tags="$(SERVER_BUILD_TAGS)" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsd-darwin-arm64 ./cmd/xkmsd/ || echo "$(YELLOW)⚠ Cross-compilation for darwin/arm64 may require macOS SDK$(RESET)"
	@echo "$(CYAN)  Building windows/amd64...$(RESET)"
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc $(GO) build -buildvcs=false -tags="$(SERVER_BUILD_TAGS)" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsd-windows-amd64.exe ./cmd/xkmsd/ || echo "$(YELLOW)⚠ Cross-compilation for windows/amd64 requires mingw-w64$(RESET)"
	@echo "$(CYAN)  Building windows/arm64...$(RESET)"
	@GOOS=windows GOARCH=arm64 CGO_ENABLED=1 $(GO) build -buildvcs=false -tags="$(SERVER_BUILD_TAGS)" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsd-windows-arm64.exe ./cmd/xkmsd/ || echo "$(YELLOW)⚠ Cross-compilation for windows/arm64 requires appropriate cross-compiler$(RESET)"
	@echo "$(GREEN)✓ xkmsd binaries built for all platforms$(RESET)"

.PHONY: lib
## lib: Build shared library (libxkms-VERSION.so) using Docker for CGO deps
lib: builder-image
	@echo "$(CYAN)$(BOLD)→ Building shared object library (version $(VERSION))...$(RESET)"
	@mkdir -p $(LIB_DIR)
	@docker run --rm \
		-v $(CURDIR):/workspace:cached \
		$(SIBLING_MOUNTS) \
		-w /workspace \
		$(BUILDER_IMAGE) \
		bash -c "CGO_ENABLED=1 go build -buildvcs=false -tags '$(BUILD_TAGS)' -ldflags '$(LDFLAGS)' -buildmode=c-shared -o $(SHARED_LIB) $(CGO_SOURCE)/main.go"
	@echo "$(GREEN)✓ Shared library built: $(SHARED_LIB)$(RESET)"
	@rm -f $(SHARED_LIB_LINK)
	@cd $(LIB_DIR) && ln -s libxkms-$(VERSION).so libxkms.so
	@echo "$(GREEN)✓ Symlink created: $(SHARED_LIB_LINK) -> libxkms-$(VERSION).so$(RESET)"

.PHONY: test
## test: Run unit tests with coverage (fast, in-memory, no system modifications)
test:
	@echo "$(CYAN)$(BOLD)→ Running unit tests...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@bash -c 'set -o pipefail; \
	$(GO) test $(TEST_FLAGS) -coverprofile=$(COVERAGE_FILE) -covermode=atomic \
		$$(go list -e ./pkg/... ./cmd/... ./sdk/... 2>/dev/null | grep -v -E "(pkg/awskms|pkg/azurekv|pkg/gcpkms|pkg/pkcs11|pkg/tpm2$$|pkg/logging|/mocks|/quantum|pkg/storage/hardware|pkg/fido2|pkg/crypto/rand|/testutil|/frost$$|/proto|cmd/xkmsd|cmd/pkcs11-module|cmd/cgo|pkcs11test|yubikey|smartcardhsm)") \
		2>&1 | tee $(COVERAGE_DIR)/test.log; \
	EXIT_CODE=$${PIPESTATUS[0]}; \
	if [ $$EXIT_CODE -eq 0 ]; then \
		echo "$(GREEN)$(BOLD)✓ All unit tests passed!$(RESET)"; \
		$(MAKE) --no-print-directory coverage-report; \
	else \
		echo "$(RED)$(BOLD)✗ Unit tests failed with exit code $$EXIT_CODE$(RESET)"; \
		cat $(COVERAGE_DIR)/test.log | grep -E "FAIL|panic" | head -20; \
		exit $$EXIT_CODE; \
	fi'

.PHONY: test-all
## test-all: Run ALL unit tests including hardware backends and import/export
test-all: test test-importexport
	@echo "$(GREEN)$(BOLD)✓ All unit tests (including hardware backends) complete!$(RESET)"

.PHONY: race
## race: Run tests with race detector on all backends (matches GitHub Actions)
race:
	@echo "$(CYAN)$(BOLD)→ Running race detector tests with all backends...$(RESET)"
	@CGO_ENABLED=1 $(GO) test -race -short -tags="pkcs8,awskms,gcpkms,azurekv,pkcs11,vault,codec_cbor,codec_json,codec_msgpack" ./... || \
		(echo "$(RED)$(BOLD)✗ Race detector found issues$(RESET)" && exit 1)
	@echo "$(GREEN)$(BOLD)✓ Race detector tests passed!$(RESET)"

.PHONY: coverage
## coverage: Generate test coverage report (unit tests only, fast)
coverage: test

.PHONY: coverage-full
## coverage-full: Generate comprehensive coverage report (unit + integration tests)
coverage-full:
	@echo "$(CYAN)$(BOLD)→ Running comprehensive coverage tests (unit + integration)...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Step 1: Running unit tests with coverage...$(RESET)"
	@$(GO) test $(TEST_FLAGS) -coverprofile=$(COVERAGE_DIR)/unit.out -covermode=atomic \
		$$(go list -e ./pkg/... 2>/dev/null | grep -v -E "(pkg/awskms|pkg/azurekv|pkg/gcpkms|pkg/pkcs11|pkg/tpm2|pkg/logging|/mocks|/quantum|pkg/storage/hardware|pkg/fido2|pkg/crypto/rand)") \
		2>&1 | tee $(COVERAGE_DIR)/unit.log || true
	@echo "$(CYAN)→ Step 2: Running integration tests with coverage...$(RESET)"
	@$(GOTEST) -v -tags="integration codec_cbor codec_json codec_msgpack" -coverprofile=$(COVERAGE_DIR)/integration.out -covermode=atomic \
		./test/integration/signing/... \
		./test/integration/opaque/... \
		./test/integration/metrics/... \
		./test/integration/health/... \
		./test/integration/ratelimit/... \
		./test/integration/correlation/... \
		./test/integration/crypto/... \
		./test/integration/xkms/... \
		./test/integration/encoding/... \
		./test/integration/backend/... \
		./test/integration/certstore/... \
		./pkg/webauthn/... \
		2>&1 | tee $(COVERAGE_DIR)/integration.log || true
	@echo "$(CYAN)→ Step 3: Merging coverage profiles...$(RESET)"
	@echo "mode: atomic" > $(COVERAGE_FILE)
	@tail -n +2 $(COVERAGE_DIR)/unit.out >> $(COVERAGE_FILE) 2>/dev/null || true
	@tail -n +2 $(COVERAGE_DIR)/integration.out >> $(COVERAGE_FILE) 2>/dev/null || true
	@$(MAKE) --no-print-directory coverage-report
	@echo "$(GREEN)$(BOLD)✓ Comprehensive coverage report complete!$(RESET)"

coverage-report:
	@if [ -f "$(COVERAGE_FILE)" ]; then \
		echo "$(CYAN)→ Generating coverage report...$(RESET)"; \
		$(GO) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML); \
		$(GO) tool cover -func=$(COVERAGE_FILE) > $(COVERAGE_DIR)/coverage.txt; \
		TOTAL=$$(grep '^total:' $(COVERAGE_DIR)/coverage.txt | awk '{print $$NF}'); \
		echo "$(GREEN)✓ Coverage report: $(COVERAGE_HTML)$(RESET)"; \
		echo ""; \
		echo "$(CYAN)====================================$(RESET)"; \
		echo "$(CYAN)Total project coverage: $${TOTAL}$(RESET)"; \
		echo "$(CYAN)====================================$(RESET)"; \
		NUMERIC=$$(echo "$${TOTAL}" | tr -d '%'); \
		THRESHOLD_CHECK=$$(echo "$${NUMERIC} < $(COVERAGE_THRESHOLD)" | bc -l 2>/dev/null | cut -d. -f1); \
		if [ "$${THRESHOLD_CHECK}" = "1" ]; then \
			echo "$(RED)FAIL: Coverage $${TOTAL} is below threshold $(COVERAGE_THRESHOLD)%$(RESET)"; \
		else \
			echo "$(GREEN)PASS: Coverage $${TOTAL} meets threshold $(COVERAGE_THRESHOLD)%$(RESET)"; \
		fi; \
	else \
		echo "$(RED)✗ Coverage file not found. Run 'make test' first.$(RESET)"; \
	fi

# ==============================================================================
# Package-Specific Unit Tests
# ==============================================================================

.PHONY: test-backend
## test-backend: Run backend package unit tests
test-backend:
	@echo "$(CYAN)→ Testing backend package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/backend/...

.PHONY: test-xkms
## test-xkms: Run xkms package unit tests
test-xkms:
	@echo "$(CYAN)→ Testing xkms package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/xkms/...

.PHONY: test-storage
## test-storage: Run storage package unit tests
test-storage:
	@echo "$(CYAN)→ Testing storage package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/storage/...

.PHONY: test-signing
## test-signing: Run signing package unit tests
test-signing:
	@echo "$(CYAN)→ Testing signing package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/signing/...

.PHONY: test-verification
## test-verification: Run verification package unit tests
test-verification:
	@echo "$(CYAN)→ Testing verification package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/verification/...

.PHONY: test-certstore
## test-certstore: Run certstore package unit tests
test-certstore:
	@echo "$(CYAN)→ Testing certstore package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/certstore/...

.PHONY: test-encoding
## test-encoding: Run encoding package unit tests
test-encoding:
	@echo "$(CYAN)→ Testing encoding package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/encoding/...

.PHONY: test-jwk
## test-jwk: Run JWK (JSON Web Key) package unit tests
test-jwk:
	@echo "$(CYAN)→ Testing JWK package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/encoding/jwk/...

.PHONY: test-jwt
## test-jwt: Run JWT (JSON Web Token) package unit tests
test-jwt:
	@echo "$(CYAN)→ Testing JWT package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/encoding/jwt/...

.PHONY: test-jwe
## test-jwe: Run JWE (JSON Web Encryption) package unit tests
test-jwe:
	@echo "$(CYAN)→ Testing JWE package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/encoding/jwe/...

.PHONY: test-ecdh
## test-ecdh: Run ECDH (Elliptic Curve Diffie-Hellman) package unit tests
test-ecdh:
	@echo "$(CYAN)→ Testing ECDH package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/crypto/ecdh/...

.PHONY: test-ecies
## test-ecies: Run ECIES (Elliptic Curve Integrated Encryption Scheme) package unit tests
test-ecies:
	@echo "$(CYAN)→ Testing ECIES package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/crypto/ecies/...

.PHONY: test-x25519
## test-x25519: Run X25519 key agreement package unit tests
test-x25519:
	@echo "$(CYAN)→ Testing X25519 package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/crypto/x25519/...

.PHONY: test-chacha20poly1305
## test-chacha20poly1305: Run ChaCha20-Poly1305 AEAD package unit tests
test-chacha20poly1305:
	@echo "$(CYAN)→ Testing ChaCha20-Poly1305 package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/crypto/chacha20poly1305/...

.PHONY: test-software
## test-software: Run unified software backend unit tests
test-software:
	@echo "$(CYAN)→ Testing unified software backend...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/backend/software/...


.PHONY: test-quantum
## test-quantum: Run all quantum-safe cryptography unit tests (backend, software routing, PKCS11, threshold, CA)
test-quantum: test-quantum-backend test-quantum-software test-quantum-pkcs11 test-quantum-pkcs11-module test-quantum-threshold test-quantum-ca test-quantum-primitives
	@echo "$(GREEN)$(BOLD)✓ All quantum unit tests complete!$(RESET)"

.PHONY: test-quantum-backend
## test-quantum-backend: Run quantum backend unit tests (ML-DSA keygen/sign, ML-KEM encap/decap, encryption)
test-quantum-backend:
	@echo "$(CYAN)→ Testing quantum backend...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/keyprovider/quantum/...

.PHONY: test-quantum-software
## test-quantum-software: Run quantum routing tests through the software backend facade
test-quantum-software:
	@echo "$(CYAN)→ Testing quantum routing through software backend...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/backend/software/... -run "MLDSA|MLKEM|Quantum|Encapsulat"

.PHONY: test-quantum-pkcs11
## test-quantum-pkcs11: Run PKCS11 backend quantum capability detection and key generation tests
test-quantum-pkcs11:
	@echo "$(CYAN)→ Testing PKCS11 quantum capabilities...$(RESET)"
	@$(GO) test -v -tags="pkcs11 codec_cbor codec_json codec_msgpack tpm_simulator" ./pkg/backend/pkcs11/... -run "Quantum|MLDSA|MLKEM"

.PHONY: test-quantum-pkcs11-module
## test-quantum-pkcs11-module: Run PKCS11 module quantum mechanism, crypto, and KEM tests
test-quantum-pkcs11-module:
	@echo "$(CYAN)→ Testing PKCS11 module quantum mechanisms...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/pkcs11/module/... -run "Quantum|MLDSA|MLKEM|Encapsulat"

.PHONY: test-quantum-threshold
## test-quantum-threshold: Run threshold backend quantum key generation, signing, and marshal tests
test-quantum-threshold:
	@echo "$(CYAN)→ Testing threshold quantum operations...$(RESET)"
	@$(GO) test -v -tags="frost codec_cbor codec_json codec_msgpack tpm_simulator" ./pkg/keyprovider/threshold/... -run "Quantum|MLDSA"

.PHONY: test-quantum-ca
## test-quantum-ca: Run CA quantum signing (ML-DSA certificates) and hybrid certificate tests
test-quantum-ca:
	@echo "$(CYAN)→ Testing CA quantum signing and hybrid certificates...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/ca/... -run "Quantum|SignCertificateWithQuantum|VerifyQuantum|OID|Hybrid"

.PHONY: test-quantum-primitives
## test-quantum-primitives: Run low-level quantum primitive tests (Kyber768, ML-KEM-1024)
test-quantum-primitives:
	@echo "$(CYAN)→ Testing quantum primitives...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/quantum/...

.PHONY: test-ca
## test-ca: Run all CA package unit tests (signing, CSR, TLS, revocation, quantum, hybrid)
test-ca:
	@echo "$(CYAN)→ Testing CA package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/ca/...

.PHONY: coverage-quantum
## coverage-quantum: Generate coverage report for quantum backend
coverage-quantum:
	@echo "$(CYAN)→ Generating quantum backend coverage...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GO) test $(TAG_FLAGS) ./pkg/keyprovider/quantum/... -coverprofile=$(COVERAGE_DIR)/quantum.out -covermode=atomic
	@$(GO) tool cover -html=$(COVERAGE_DIR)/quantum.out -o $(COVERAGE_DIR)/quantum-coverage.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/quantum.out > $(COVERAGE_DIR)/quantum.txt
	@TOTAL=$$(grep '^total:' $(COVERAGE_DIR)/quantum.txt | awk '{print $$NF}'); \
	echo "$(CYAN)quantum coverage: $${TOTAL}$(RESET)"
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/quantum-coverage.html$(RESET)"

.PHONY: coverage-ca
## coverage-ca: Generate coverage report for CA package
coverage-ca:
	@echo "$(CYAN)→ Generating CA coverage...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GO) test $(TAG_FLAGS) ./pkg/ca/... -coverprofile=$(COVERAGE_DIR)/ca.out -covermode=atomic
	@$(GO) tool cover -html=$(COVERAGE_DIR)/ca.out -o $(COVERAGE_DIR)/ca-coverage.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/ca.out > $(COVERAGE_DIR)/ca.txt
	@TOTAL=$$(grep '^total:' $(COVERAGE_DIR)/ca.txt | awk '{print $$NF}'); \
	echo "$(CYAN)ca coverage: $${TOTAL}$(RESET)"
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/ca-coverage.html$(RESET)"

.PHONY: bench-quantum
## bench-quantum: Run quantum backend benchmarks
bench-quantum:
	@echo "$(CYAN)$(BOLD)→ Running quantum backend benchmarks...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=Benchmark -benchmem -benchtime=3s -run=^$$ \
		./pkg/keyprovider/quantum/... | tee $(BENCH_DIR)/quantum.txt
	@echo "$(GREEN)✓ Quantum benchmarks complete$(RESET)"
	@echo "$(CYAN)Results saved to: $(BENCH_DIR)/quantum.txt$(RESET)"

.PHONY: test-symmetric
## test-symmetric: Run symmetric encryption package unit tests
test-symmetric:
	@echo "$(CYAN)→ Testing symmetric encryption package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/keyprovider/symmetric/...

.PHONY: test-wrapping
## test-wrapping: Run key wrapping cryptographic primitives unit tests
test-wrapping:
	@echo "$(CYAN)→ Testing key wrapping primitives...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/crypto/wrapping/...

.PHONY: test-rand
## test-rand: Run crypto/rand package unit tests (software only)
test-rand:
	@echo "$(CYAN)→ Testing crypto/rand package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/crypto/rand/...

.PHONY: test-backup
## test-backup: Run backup adapter unit tests
test-backup:
	@echo "$(CYAN)→ Testing backup adapter...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/adapters/backup/...

.PHONY: coverage-backup
## coverage-backup: Generate coverage report for backup adapter
coverage-backup:
	@echo "$(CYAN)→ Generating coverage report for backup adapter...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/backup.out -covermode=atomic ./pkg/adapters/backup/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/backup.out -o $(COVERAGE_DIR)/backup.html
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/backup.html$(RESET)"

.PHONY: bench-backup
## bench-backup: Run backup adapter benchmarks
bench-backup:
	@echo "$(CYAN)→ Running backup adapter benchmarks...$(RESET)"
	@$(GOTEST) -bench=. -benchmem -run=^$$ ./pkg/adapters/backup/...

.PHONY: test-rand-tpm2
## test-rand-tpm2: Run crypto/rand package unit tests with TPM2 simulator support
test-rand-tpm2:
	@echo "$(CYAN)→ Testing crypto/rand package with TPM2 simulator...$(RESET)"
	@$(GO) test -tags= $(TEST_FLAGS) ./pkg/crypto/rand/...

.PHONY: test-rand-all
## test-rand-all: Run all crypto/rand unit tests (software + TPM2)
test-rand-all: test-rand test-rand-tpm2
	@echo "$(GREEN)✓ All crypto/rand unit tests complete$(RESET)"

.PHONY: test-importexport
## test-importexport: Run import/export unit tests for all backends
test-importexport:
	@echo "$(CYAN)→ Testing import/export functionality...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/crypto/wrapping/...
	@echo "$(CYAN)→ Testing software backend import/export...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/backend/software/... -run "Test.*Import|Test.*Export"
	@echo "$(CYAN)→ Testing symmetric backend import/export...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/keyprovider/symmetric/... -run "Test.*Import|Test.*Export"
	@echo "$(CYAN)→ Testing AWS KMS backend import/export...$(RESET)"
	@$(GO) test -tags=awskms $(TEST_FLAGS) ./pkg/backend/awskms/... -run "Test.*Import|Test.*Export|Test.*Wrap"
	@echo "$(CYAN)→ Testing GCP KMS backend import/export...$(RESET)"
	@$(GO) test -tags=gcpkms $(TEST_FLAGS) ./pkg/backend/gcpkms/... -run "Test.*Import|Test.*Export|Test.*Wrap"
	@echo "$(CYAN)→ Testing TPM2 backend import/export...$(RESET)"
	@$(GO) test -tags= $(TEST_FLAGS) ./pkg/tpm2/... -run "Test.*Import|Test.*Export"
	@echo "$(CYAN)→ Testing PKCS#11 backend import/export...$(RESET)"
	@$(GO) test -tags=pkcs11 $(TEST_FLAGS) ./pkg/backend/pkcs11/... -run "Test.*Import|Test.*Export|TestCapabilities"

.PHONY: test-migration
## test-migration: Run key migration unit tests
test-migration:
	@echo "$(CYAN)→ Testing key migration package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/migration/...

.PHONY: coverage-migration
## coverage-migration: Generate coverage report for key migration package
coverage-migration:
	@echo "$(CYAN)→ Generating coverage report for key migration...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/migration.out -covermode=atomic ./pkg/migration/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/migration.out -o $(COVERAGE_DIR)/migration.html
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/migration.html$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/migration.out | grep total


.PHONY: test-sdk-go
## test-sdk-go: Run Go SDK unit tests (separate module at sdk/go)
test-sdk-go:
	@echo "$(CYAN)→ Testing Go SDK package...$(RESET)"
	@cd sdk/go && $(GO) test $(TEST_FLAGS) ./...
	@echo "$(GREEN)✓ Go SDK unit tests complete$(RESET)"

.PHONY: test-sdk-transport
## test-sdk-transport: Run Go SDK REST transport unit tests (custodian, share, tenant)
test-sdk-transport:
	@echo "$(CYAN)→ Testing Go SDK REST transport methods...$(RESET)"
	@cd sdk/go && $(GO) test -v -count=1 ./transport/rest/... -timeout 5m
	@echo "$(GREEN)✓ Go SDK REST transport tests complete$(RESET)"

.PHONY: coverage-sdk-go
## coverage-sdk-go: Generate coverage report for Go SDK
coverage-sdk-go:
	@echo "$(CYAN)→ Generating coverage report for Go SDK...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@cd sdk/go && $(GO) test -race -coverprofile=../../$(COVERAGE_DIR)/sdk-go.out -covermode=atomic ./...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/sdk-go.out -o $(COVERAGE_DIR)/sdk-go.html
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/sdk-go.html$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/sdk-go.out | grep total

# ==============================================================================
# Auth, Authz, Audit, RBAC, User, and CLI Unit Tests
# ==============================================================================

.PHONY: test-auth
## test-auth: Run auth adapter unit tests
test-auth:
	@echo "$(CYAN)→ Testing auth adapters...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/adapters/auth/...
	@echo "$(GREEN)✓ Auth adapter tests complete$(RESET)"

.PHONY: coverage-auth
## coverage-auth: Generate coverage report for auth adapters
coverage-auth:
	@echo "$(CYAN)→ Generating coverage report for auth adapters...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/auth.out -covermode=atomic ./pkg/adapters/auth/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/auth.out -o $(COVERAGE_DIR)/auth.html
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/auth.html$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/auth.out | grep total

.PHONY: test-authz
## test-authz: Run authz adapter unit tests
test-authz:
	@echo "$(CYAN)→ Testing authz adapters...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/adapters/authz/...
	@echo "$(GREEN)✓ Authz adapter tests complete$(RESET)"

.PHONY: coverage-authz
## coverage-authz: Generate coverage report for authz adapters
coverage-authz:
	@echo "$(CYAN)→ Generating coverage report for authz adapters...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/authz.out -covermode=atomic ./pkg/adapters/authz/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/authz.out -o $(COVERAGE_DIR)/authz.html
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/authz.html$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/authz.out | grep total

.PHONY: test-audit
## test-audit: Run audit adapter unit tests
test-audit:
	@echo "$(CYAN)→ Testing audit adapters...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/adapters/audit/...
	@echo "$(GREEN)✓ Audit adapter tests complete$(RESET)"

.PHONY: coverage-audit
## coverage-audit: Generate coverage report for audit adapters
coverage-audit:
	@echo "$(CYAN)→ Generating coverage report for audit adapters...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/audit.out -covermode=atomic ./pkg/adapters/audit/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/audit.out -o $(COVERAGE_DIR)/audit.html
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/audit.html$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/audit.out | grep total

.PHONY: test-user
## test-user: Run user package unit tests
test-user:
	@echo "$(CYAN)→ Testing user package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/user/...
	@echo "$(GREEN)✓ User package tests complete$(RESET)"

.PHONY: coverage-user
## coverage-user: Generate coverage report for user package
coverage-user:
	@echo "$(CYAN)→ Generating coverage report for user package...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/user.out -covermode=atomic ./pkg/user/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/user.out -o $(COVERAGE_DIR)/user.html
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/user.html$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/user.out | grep total

.PHONY: test-rbac
## test-rbac: Run RBAC adapter unit tests
test-rbac:
	@echo "$(CYAN)→ Testing RBAC adapters...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/adapters/rbac/...
	@echo "$(GREEN)✓ RBAC adapter tests complete$(RESET)"

.PHONY: coverage-rbac
## coverage-rbac: Generate coverage report for RBAC adapters
coverage-rbac:
	@echo "$(CYAN)→ Generating coverage report for RBAC adapters...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/rbac.out -covermode=atomic ./pkg/adapters/rbac/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/rbac.out -o $(COVERAGE_DIR)/rbac.html
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/rbac.html$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/rbac.out | grep total

.PHONY: test-xkmsctl
## test-xkmsctl: Run xkmsctl CLI unit tests
test-xkmsctl:
	@echo "$(CYAN)→ Testing xkmsctl CLI...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./cmd/xkmsctl/...
	@echo "$(GREEN)✓ Xkmsctl CLI tests complete$(RESET)"

.PHONY: test-seal
## test-seal: Run seal package unit tests
test-seal:
	@echo "$(CYAN)→ Testing seal package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/seal/...
	@echo "$(GREEN)✓ Seal tests complete$(RESET)"

.PHONY: test-mem
## test-mem: Run crypto mem package unit tests
test-mem:
	@echo "$(CYAN)→ Testing crypto mem package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/crypto/mem/...
	@echo "$(GREEN)✓ Crypto mem tests complete$(RESET)"

.PHONY: coverage-seal
## coverage-seal: Generate coverage report for seal package
coverage-seal:
	@echo "$(CYAN)→ Generating coverage report for seal package...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/seal.out -covermode=atomic ./pkg/seal/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/seal.out -o $(COVERAGE_DIR)/seal.html
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/seal.html$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/seal.out | grep total

.PHONY: coverage-mem
## coverage-mem: Generate coverage report for crypto mem package
coverage-mem:
	@echo "$(CYAN)→ Generating coverage report for crypto mem package...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/mem.out -covermode=atomic ./pkg/crypto/mem/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/mem.out -o $(COVERAGE_DIR)/mem.html
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/mem.html$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/mem.out | grep total

.PHONY: coverage-xkmsctl
## coverage-xkmsctl: Generate coverage report for xkmsctl CLI
coverage-xkmsctl:
	@echo "$(CYAN)→ Generating coverage report for xkmsctl CLI...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/xkmsctl.out -covermode=atomic ./cmd/xkmsctl/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/xkmsctl.out -o $(COVERAGE_DIR)/xkmsctl.html
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/xkmsctl.html$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/xkmsctl.out | grep total

.PHONY: integration-test
## integration-test: Run all integration tests (all backends + all API protocols)

integration-test: clean-test-containers integration-test-software integration-test-pkcs8 integration-test-pkcs11 integration-test-tpm2 integration-test-awskms integration-test-gcpkms integration-test-azurekv integration-test-vault integration-test-storage integration-test-utils integration-test-quantum integration-test-frost integration-test-webauthn integration-test-fido2 integration-test-cli integration-test-api-all integration-test-sdk-go integration-test-bootstrap
	@echo "$(GREEN)$(BOLD)✓ All integration tests complete!$(RESET)"

.PHONY: clean-test-containers
## clean-test-containers: Clean up Docker containers from previous test runs
clean-test-containers:
	@echo "$(CYAN)→ Cleaning up test containers...$(RESET)"
	@bash test/scripts/clean-test-containers.sh >/dev/null 2>&1 || true
	@echo "$(GREEN)✓ Test containers cleaned$(RESET)"

# ==============================================================================
# Storage Integration Tests
# ==============================================================================

.PHONY: integration-test-storage
## integration-test-storage: Run all storage integration tests
integration-test-storage: integration-test-storage-file integration-test-storage-memory integration-test-storage-hardware
	@echo "$(GREEN)$(BOLD)✓ All storage integration tests complete!$(RESET)"

.PHONY: integration-test-storage-file
## integration-test-storage-file: Run file storage integration tests
integration-test-storage-file:
	@echo "$(CYAN)$(BOLD)→ Running file storage integration tests...$(RESET)"
	@cd test/integration/storage && docker compose down -v >/dev/null 2>&1 || true
	@cd test/integration/storage && (docker compose run --rm test-file; EXIT_CODE=$$?; docker compose down -v; exit $$EXIT_CODE)
	@echo "$(GREEN)✓ File storage integration tests complete$(RESET)"

.PHONY: integration-test-storage-memory
## integration-test-storage-memory: Run memory storage integration tests
integration-test-storage-memory:
	@echo "$(CYAN)$(BOLD)→ Running memory storage integration tests...$(RESET)"
	@cd test/integration/storage && docker compose down -v >/dev/null 2>&1 || true
	@cd test/integration/storage && (docker compose run --rm test-memory; EXIT_CODE=$$?; docker compose down -v; exit $$EXIT_CODE)
	@echo "$(GREEN)✓ Memory storage integration tests complete$(RESET)"

.PHONY: integration-test-storage-hardware
## integration-test-storage-hardware: Run hardware storage integration tests (PKCS#11 + TPM2)
integration-test-storage-hardware: integration-test-storage-hardware-pkcs11 integration-test-storage-hardware-tpm2
	@echo "$(GREEN)✓ Hardware storage integration tests complete$(RESET)"

.PHONY: integration-test-storage-hardware-pkcs11
## integration-test-storage-hardware-pkcs11: Run PKCS#11 hardware storage tests
integration-test-storage-hardware-pkcs11:
	@echo "$(CYAN)$(BOLD)→ Running PKCS#11 hardware storage tests...$(RESET)"
	@cd test/integration/storage && docker compose down -v >/dev/null 2>&1 || true
	@cd test/integration/storage && docker compose up -d softhsm-init
	@sleep 2
	@cd test/integration/storage && (docker compose run --rm test-hardware-pkcs11; EXIT_CODE=$$?; docker compose down -v; exit $$EXIT_CODE)
	@echo "$(GREEN)✓ PKCS#11 hardware storage tests complete$(RESET)"

.PHONY: integration-test-storage-hardware-tpm2
## integration-test-storage-hardware-tpm2: Run TPM2 hardware storage tests
integration-test-storage-hardware-tpm2:
	@echo "$(CYAN)$(BOLD)→ Running TPM2 hardware storage tests...$(RESET)"
	@cd test/integration/storage && docker compose down -v >/dev/null 2>&1 || true
	@cd test/integration/storage && docker compose up -d tpm-simulator
	@sleep 3
	@cd test/integration/storage && (docker compose run --rm test-hardware-tpm2; EXIT_CODE=$$?; docker compose down -v; exit $$EXIT_CODE)
	@echo "$(GREEN)✓ TPM2 hardware storage tests complete$(RESET)"

# ==============================================================================
# Real Hardware Integration Tests
# ==============================================================================

.PHONY: integration-test-hw-storage-pkcs11
## integration-test-hw-storage-pkcs11: Run real PKCS#11 hardware storage tests (requires physical device)
integration-test-hw-storage-pkcs11:
	@echo "$(CYAN)$(BOLD)→ Running real PKCS#11 hardware storage tests...$(RESET)"
	@echo "$(YELLOW)NOTE: This requires real PKCS#11 hardware (YubiKey, Nitrokey, etc.) connected to the host$(RESET)"
	@echo "$(YELLOW)Set PKCS11_LIB and PKCS11_PIN environment variables$(RESET)"
	go test -v -tags='hw_integration,pkcs11,codec_cbor,codec_json,codec_msgpack' ./test/integration/storage -run TestRealPKCS11Hardware -timeout 15m
	@echo "$(GREEN)✓ Real PKCS#11 hardware storage tests complete$(RESET)"

.PHONY: integration-test-hw-storage-tpm2
## integration-test-hw-storage-tpm2: Run real TPM2 hardware storage tests (requires physical TPM)
integration-test-hw-storage-tpm2:
	@echo "$(CYAN)$(BOLD)→ Running real TPM2 hardware storage tests...$(RESET)"
	@echo "$(YELLOW)NOTE: This requires real TPM2 hardware (/dev/tpm0 or /dev/tpmrm0)$(RESET)"
	go test -v -tags='hw_integration,codec_cbor,codec_json,codec_msgpack' ./test/integration/storage -run TestRealTPM2Hardware -timeout 15m
	@echo "$(GREEN)✓ Real TPM2 hardware storage tests complete$(RESET)"

.PHONY: coverage-storage
## coverage-storage: Generate coverage report for all storage packages
coverage-storage: coverage-file-storage coverage-memory-storage coverage-hardware-storage
	@echo "$(GREEN)$(BOLD)✓ All storage coverage reports generated!$(RESET)"

.PHONY: coverage-file-storage
## coverage-file-storage: Generate file storage coverage report
coverage-file-storage:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating file storage coverage report...$(RESET)"
	@$(GO) test -v -tags=integration -coverprofile=$(COVERAGE_DIR)/file-storage.out -covermode=atomic \
		./pkg/storage/file/... ./test/integration/storage/... -run 'TestFileStorage'
	@$(GO) tool cover -html=$(COVERAGE_DIR)/file-storage.out -o $(COVERAGE_DIR)/file-storage.html
	@echo "$(GREEN)✓ File storage coverage report generated$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/file-storage.out | grep total

.PHONY: coverage-memory-storage
## coverage-memory-storage: Generate memory storage coverage report
coverage-memory-storage:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating memory storage coverage report...$(RESET)"
	@$(GO) test -v -tags=integration -coverprofile=$(COVERAGE_DIR)/memory-storage.out -covermode=atomic \
		./pkg/storage/memory/... ./test/integration/storage/... -run 'TestMemoryStorage'
	@$(GO) tool cover -html=$(COVERAGE_DIR)/memory-storage.out -o $(COVERAGE_DIR)/memory-storage.html
	@echo "$(GREEN)✓ Memory storage coverage report generated$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/memory-storage.out | grep total

.PHONY: coverage-hardware-storage
## coverage-hardware-storage: Generate hardware storage coverage report
coverage-hardware-storage:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating hardware storage coverage report...$(RESET)"
	@$(GO) test -v -tags='integration,pkcs11' -coverprofile=$(COVERAGE_DIR)/hardware-storage.out -covermode=atomic \
		./pkg/storage/hardware/... ./test/integration/storage/... -run 'TestHardwareStorage'
	@$(GO) tool cover -html=$(COVERAGE_DIR)/hardware-storage.out -o $(COVERAGE_DIR)/hardware-storage.html
	@echo "$(GREEN)✓ Hardware storage coverage report generated$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/hardware-storage.out | grep total

# ==============================================================================
# Cloud Service Emulator Management
# ==============================================================================

EMULATOR_COMPOSE := docker compose -f docker-compose.emulators.yml

.PHONY: emulator-start
## emulator-start: Start cloud service emulators
emulator-start:
	@bash test/scripts/setup-azure-emulator-certs.sh
	@$(EMULATOR_COMPOSE) up -d
	@sleep 15

.PHONY: emulator-stop
## emulator-stop: Stop and remove emulator containers
emulator-stop:
	@$(EMULATOR_COMPOSE) down -v 2>/dev/null || true
	@cd $(API_TEST_DIR) && docker compose down -v 2>/dev/null || true
	@docker stop $$(docker ps -q --filter "name=localstack") 2>/dev/null || true
	@docker stop $$(docker ps -q --filter "name=xkms") 2>/dev/null || true
	@docker stop $$(docker ps -q --filter "name=azure") 2>/dev/null || true
	@docker stop $$(docker ps -q --filter "name=gcp") 2>/dev/null || true
	@docker stop $$(docker ps -q --filter "name=vault") 2>/dev/null || true
	@docker rm $$(docker ps -aq --filter "name=localstack") 2>/dev/null || true
	@docker rm $$(docker ps -aq --filter "name=xkms") 2>/dev/null || true
	@docker rm $$(docker ps -aq --filter "name=azure") 2>/dev/null || true
	@docker rm $$(docker ps -aq --filter "name=gcp") 2>/dev/null || true
	@docker rm $$(docker ps -aq --filter "name=vault") 2>/dev/null || true

.PHONY: emulator-restart
## emulator-restart: Restart emulators
emulator-restart: emulator-stop emulator-start

.PHONY: emulator-status
## emulator-status: Check emulator health
emulator-status:
	@$(EMULATOR_COMPOSE) ps
	@echo ""
	@curl -s http://localhost:4566/_localstack/health 2>/dev/null | jq -C '.' || echo "LocalStack: Not responding"
	@curl -s -k https://localhost:4997/health >/dev/null 2>&1 && echo "Azure KV: Running" || echo "Azure KV: Not responding"

.PHONY: emulator-logs
## emulator-logs: View emulator logs
emulator-logs:
	@$(EMULATOR_COMPOSE) logs -f

.PHONY: emulator-clean
## emulator-clean: Stop emulators and clean data
emulator-clean: emulator-stop
	@rm -rf ${TMPDIR:-/tmp}/localstack .azure-emulator

# ==============================================================================
# Package-Specific Integration Tests
# ==============================================================================

.PHONY: integration-test-software
## integration-test-software: Run unified software backend integration tests (runs in devcontainer)
integration-test-software:
	$(call run_in_devcontainer,$(GO) test -v -tags=integration ./pkg/backend/software/... -timeout 5m,integration-test-software)

.PHONY: integration-test-symmetric
## integration-test-symmetric: Run symmetric backend integration tests (runs in devcontainer)
integration-test-symmetric:
	$(call run_in_devcontainer,$(GO) test -v -tags=integration ./pkg/keyprovider/symmetric/... -timeout 5m,integration-test-symmetric)

.PHONY: integration-test-pkcs8
## integration-test-pkcs8: Run PKCS8 asymmetric backend integration tests
integration-test-pkcs8:
	@echo "$(CYAN)$(BOLD)→ Running PKCS8 integration tests...$(RESET)"
	@cd test/integration/pkcs8 && docker compose down -v >/dev/null 2>&1 || true
	@cd test/integration/pkcs8 && (docker compose run --rm test; EXIT_CODE=$$?; docker compose down -v; exit $$EXIT_CODE)
	@echo "$(GREEN)✓ PKCS8 integration tests complete$(RESET)"

.PHONY: integration-test-pkcs11
## integration-test-pkcs11: Run PKCS11/SoftHSM integration tests
integration-test-pkcs11:
	@echo "$(CYAN)$(BOLD)→ Running PKCS11/SoftHSM integration tests...$(RESET)"
	@cd test/integration/pkcs11 && docker compose down -v >/dev/null 2>&1 || true
	@cd test/integration/pkcs11 && (docker compose run --build --rm test; EXIT_CODE=$$?; docker compose down -v; exit $$EXIT_CODE)
	@echo "$(GREEN)✓ PKCS11 integration tests complete$(RESET)"

.PHONY: integration-test-pkcs11-module
## integration-test-pkcs11-module: Run PKCS#11 module multi-protocol integration tests (runs in devcontainer with xkms-server)
integration-test-pkcs11-module:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) $(GO) test -v -tags='integration' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT),integration-test-pkcs11-module)

.PHONY: integration-test-pkcs11-module-unix
## integration-test-pkcs11-module-unix: Run PKCS#11 multi-protocol tests with Unix socket target (runs in devcontainer with xkms-server)
integration-test-pkcs11-module-unix:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_PKCS11_TARGET=unix://$(XKMS_UNIX_SOCKET) $(GO) test -v -tags='integration' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT) -run 'TestMultiProtocol',integration-test-pkcs11-module-unix)

.PHONY: integration-test-pkcs11-module-grpc
## integration-test-pkcs11-module-grpc: Run PKCS#11 multi-protocol tests with gRPC target (runs in devcontainer with xkms-server)
integration-test-pkcs11-module-grpc:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) XKMS_PKCS11_TARGET=$(XKMS_GRPC_ADDR_CONTAINER) $(GO) test -v -tags='integration' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT) -run 'TestMultiProtocol',integration-test-pkcs11-module-grpc)

.PHONY: integration-test-pkcs11-module-compat
## integration-test-pkcs11-module-compat: Run PKCS#11 module compatibility tests with pkcs11-tool (runs in devcontainer with xkms-server)
integration-test-pkcs11-module-compat:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage $(GO) test -v -tags='integration$(comma)pkcs11$(comma)pkcs11_tool' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT) -run 'TestPKCS11Tool',integration-test-pkcs11-module-compat)

.PHONY: integration-test-pkcs11-tool
## integration-test-pkcs11-tool: Run comprehensive pkcs11-tool integration tests (runs in devcontainer with xkms-server)
integration-test-pkcs11-tool:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) $(GO) test -v -tags='integration$(comma)pkcs11$(comma)pkcs11_tool' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT) -run 'TestPKCS11Tool',integration-test-pkcs11-tool)

.PHONY: integration-test-pkcs11-openssl
## integration-test-pkcs11-openssl: Run PKCS#11 module OpenSSL integration tests (runs in devcontainer with xkms-server)
integration-test-pkcs11-openssl:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) $(GO) test -v -tags='integration$(comma)pkcs11$(comma)pkcs11_tool' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT) -run 'TestOpenSSL',integration-test-pkcs11-openssl)

.PHONY: integration-test-pkcs11-ssh
## integration-test-pkcs11-ssh: Run PKCS#11 module SSH integration tests (runs in devcontainer with xkms-server)
integration-test-pkcs11-ssh:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) $(GO) test -v -tags='integration$(comma)pkcs11$(comma)pkcs11_tool' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT) -run 'TestSSH',integration-test-pkcs11-ssh)

.PHONY: integration-test-pkcs11-compat-all
## integration-test-pkcs11-compat-all: Run ALL PKCS#11 compatibility tests (pkcs11-tool, OpenSSL, SSH)
integration-test-pkcs11-compat-all: integration-test-pkcs11-tool integration-test-pkcs11-openssl integration-test-pkcs11-ssh
	@echo "$(GREEN)$(BOLD)✓ All PKCS#11 compatibility tests complete!$(RESET)"

.PHONY: integration-test-tpm2
## integration-test-tpm2: Run TPM2 simulator integration tests
integration-test-tpm2:
	@echo "$(CYAN)$(BOLD)→ Running TPM2 simulator integration tests...$(RESET)"
	@cd test/integration/tpm2 && docker compose down -v >/dev/null 2>&1 || true
	@cd test/integration/tpm2 && docker compose up -d tpm-simulator
	@echo "$(CYAN)  Waiting for TPM simulator to be ready...$(RESET)"
	@sleep 3
	@cd test/integration/tpm2 && (docker compose run --build --rm -e TPM2_SIMULATOR_HOST=tpm-simulator -e TPM2_SIMULATOR_PORT=2421 test; EXIT_CODE=$$?; docker compose down -v; exit $$EXIT_CODE)
	@echo "$(GREEN)✓ TPM2 integration tests complete$(RESET)"

.PHONY: test-tpm2-encryption
## test-tpm2-encryption: Run TPM2 session encryption verification tests with packet capture
test-tpm2-encryption:
	@echo "$(CYAN)$(BOLD)→ Running TPM2 session encryption verification tests...$(RESET)"
	@cd test/integration/tpm2 && docker compose down -v >/dev/null 2>&1 || true
	@cd test/integration/tpm2 && docker compose up -d tpm-simulator
	@echo "$(CYAN)  Waiting for TPM simulator to be ready...$(RESET)"
	@sleep 3
	@cd test/integration/tpm2 && (docker compose run --rm -e TPM2_SIMULATOR_HOST=tpm-simulator -e TPM2_SIMULATOR_PORT=2421 test sh /app/test/integration/tpm2/run_capture_tests.sh; EXIT_CODE=$$?; docker compose down -v; exit $$EXIT_CODE)
	@echo "$(GREEN)✓ TPM2 encryption verification tests complete$(RESET)"

.PHONY: test-tpm2-encryption-local
## test-tpm2-encryption-local: Run TPM2 encryption tests locally (requires TPM device or simulator)
test-tpm2-encryption-local:
	@echo "$(CYAN)$(BOLD)→ Running TPM2 encryption tests locally...$(RESET)"
	@if [ -z "$$TPM2_SIMULATOR_HOST" ]; then \
		echo "$(YELLOW)⚠ TPM2_SIMULATOR_HOST not set, checking for hardware TPM...$(RESET)"; \
		if [ ! -e "/dev/tpmrm0" ]; then \
			echo "$(RED)✗ No TPM device found. Set TPM2_SIMULATOR_HOST or ensure /dev/tpmrm0 exists$(RESET)"; \
			exit 1; \
		fi; \
	fi
	@go test -v -tags='integration codec_cbor codec_json codec_msgpack' -run 'TestTPMSession' -timeout 30m ./test/integration/tpm2/
	@echo "$(GREEN)✓ TPM2 encryption tests complete$(RESET)"

.PHONY: integration-test-awskms
## integration-test-awskms: Run AWS KMS/LocalStack integration tests
integration-test-awskms:
	@echo "$(CYAN)$(BOLD)→ Running AWS KMS/LocalStack integration tests...$(RESET)"
	@cd test/integration/awskms && docker compose down -v >/dev/null 2>&1 || true
	@cd test/integration/awskms && docker compose up -d localstack
	@cd test/integration/awskms && (docker compose run --rm test; EXIT_CODE=$$?; docker compose down -v; exit $$EXIT_CODE)
	@echo "$(GREEN)✓ AWS KMS integration tests complete$(RESET)"

.PHONY: integration-test-gcpkms
## integration-test-gcpkms: Run GCP KMS integration tests with mock client
integration-test-gcpkms:
	@echo "$(CYAN)$(BOLD)→ Running GCP KMS integration tests with mock client...$(RESET)"
	@cd test/integration/gcpkms && docker compose down -v >/dev/null 2>&1 || true
	@cd test/integration/gcpkms && (docker compose run --rm test; EXIT_CODE=$$?; docker compose down -v; exit $$EXIT_CODE)
	@echo "$(GREEN)✓ GCP KMS integration tests complete$(RESET)"

.PHONY: integration-test-azurekv
## integration-test-azurekv: Run Azure Key Vault integration tests with mock client
integration-test-azurekv:
	@echo "$(CYAN)$(BOLD)→ Running Azure Key Vault integration tests...$(RESET)"
	@cd test/integration/azurekv && docker compose down -v >/dev/null 2>&1 || true
	@cd test/integration/azurekv && (docker compose run --rm test; EXIT_CODE=$$?; docker compose down -v; exit $$EXIT_CODE)
	@echo "$(GREEN)✓ Azure Key Vault integration tests complete$(RESET)"

.PHONY: integration-test-vault
## integration-test-vault: Run HashiCorp Vault integration tests
integration-test-vault:
	@echo "$(CYAN)$(BOLD)→ Running HashiCorp Vault integration tests...$(RESET)"
	@cd test/integration/vault && docker compose down -v >/dev/null 2>&1 || true
	@cd test/integration/vault && docker compose up -d vault
	@cd test/integration/vault && docker compose build test
	@cd test/integration/vault && (docker compose run --rm test; EXIT_CODE=$$?; docker compose down -v; exit $$EXIT_CODE)
	@echo "$(GREEN)✓ Vault integration tests complete$(RESET)"

.PHONY: integration-test-quantum
## integration-test-quantum: Run quantum-safe cryptography integration tests (ML-DSA, ML-KEM)
integration-test-quantum:
	@echo "$(CYAN)$(BOLD)→ Running quantum-safe cryptography integration tests...$(RESET)"
	@echo "$(YELLOW)Note: Testing ML-DSA signatures and ML-KEM key encapsulation$(RESET)"
	@cd test/integration/quantum && docker compose down -v >/dev/null 2>&1 || true
	@cd test/integration/quantum && docker compose build --no-cache quantum-test
	@cd test/integration/quantum && (docker compose run --rm quantum-test; EXIT_CODE=$$?; docker compose down -v; exit $$EXIT_CODE)
	@echo "$(GREEN)✓ Quantum-safe integration tests complete$(RESET)"

.PHONY: test-frost
## test-frost: Run FROST unit tests
test-frost:
ifeq ($(WITH_FROST),1)
	@echo "$(CYAN)$(BOLD)→ Running FROST unit tests...$(RESET)"
	@$(GOTEST) -v -tags="frost" ./pkg/keyprovider/frost/...
	@echo "$(GREEN)✓ FROST unit tests complete$(RESET)"
else
	@echo "$(YELLOW)⚠ Skipping FROST unit tests (WITH_FROST=0)$(RESET)"
	@echo "$(YELLOW)  To enable, run: make test-frost WITH_FROST=1$(RESET)"
endif

.PHONY: integration-test-frost
## integration-test-frost: Run FROST threshold signature integration tests
integration-test-frost:
ifeq ($(WITH_FROST),1)
	@echo "$(CYAN)$(BOLD)→ Running FROST threshold signature integration tests...$(RESET)"
	@echo "$(YELLOW)Note: Testing FROST key generation, signing rounds, and CLI commands$(RESET)"
	@cd test/integration/frost && docker compose down -v >/dev/null 2>&1 || true
	@cd test/integration/frost && docker compose build frost-test
	@cd test/integration/frost && (docker compose run --rm frost-test; EXIT_CODE=$$?; docker compose down -v; exit $$EXIT_CODE)
	@echo "$(GREEN)✓ FROST integration tests complete$(RESET)"
else
	@echo "$(YELLOW)⚠ Skipping FROST integration tests (WITH_FROST=0)$(RESET)"
	@echo "$(YELLOW)  To enable, run: make integration-test-frost WITH_FROST=1$(RESET)"
endif

.PHONY: integration-test-webauthn
## integration-test-webauthn: Run WebAuthn integration tests with virtual authenticator (runs in devcontainer)
integration-test-webauthn:
	$(call run_in_devcontainer,$(GO) test -v -tags=integration ./pkg/webauthn/... -timeout 5m,integration-test-webauthn)

# Comma for use in function calls (Make escapes commas in function args)
comma := ,

# Docker compose command for devcontainer
DOCKER_COMPOSE := docker compose -f .devcontainer/docker-compose.yml

# Helper to run command in devcontainer (auto-starts if needed)
define run_in_devcontainer
	@if [ -f "/.dockerenv" ] || [ -n "$$DEVCONTAINER" ]; then \
		$(1); \
	else \
		echo "$(CYAN)$(BOLD)→ Starting devcontainer...$(RESET)"; \
		$(DOCKER_COMPOSE) up -d devcontainer --wait 2>/dev/null || $(DOCKER_COMPOSE) up -d devcontainer; \
		echo "$(CYAN)$(BOLD)→ Running in devcontainer: $(2)$(RESET)"; \
		$(DOCKER_COMPOSE) exec -T devcontainer bash -c "cd /workspace && $(1)"; \
	fi
endef

# Helper to run command in devcontainer with xkms-server running
# Usage: $(call run_with_server,command,description)
define run_with_server
	@if [ -f "/.dockerenv" ] || [ -n "$$DEVCONTAINER" ]; then \
		echo "$(CYAN)$(BOLD)→ Building PKCS#11 shared library...$(RESET)"; \
		mkdir -p build/lib && CGO_ENABLED=1 go build -buildmode=c-shared -o build/lib/libxkms_pkcs11.so ./cmd/pkcs11-module; \
		echo "$(GREEN)✓ PKCS#11 module built: build/lib/libxkms_pkcs11.so$(RESET)"; \
		echo "$(CYAN)$(BOLD)→ Starting xkms-server...$(RESET)"; \
		$(DOCKER_COMPOSE) up -d xkms-server 2>/dev/null || true; \
		echo "$(CYAN)$(BOLD)→ Waiting for xkms-server to be ready...$(RESET)"; \
		for i in 1 2 3 4 5 6 7 8 9 10; do \
			if [ -S /var/run/xkms/xkms.sock ]; then \
				echo "$(GREEN)✓ Unix socket ready$(RESET)"; \
				break; \
			fi; \
			echo "  Waiting for socket... ($$i/10)"; \
			sleep 2; \
		done; \
		$(1); \
	else \
		echo "$(CYAN)$(BOLD)→ Starting devcontainer...$(RESET)"; \
		$(DOCKER_COMPOSE) up -d devcontainer 2>/dev/null || true; \
		echo "$(CYAN)$(BOLD)→ Building PKCS#11 shared library in devcontainer...$(RESET)"; \
		$(DOCKER_COMPOSE) exec -T devcontainer bash -c "cd /workspace && mkdir -p build/lib && CGO_ENABLED=1 go build -buildmode=c-shared -o build/lib/libxkms_pkcs11.so ./cmd/pkcs11-module"; \
		echo "$(GREEN)✓ PKCS#11 module built in devcontainer$(RESET)"; \
		echo "$(CYAN)$(BOLD)→ Starting xkms-server...$(RESET)"; \
		$(DOCKER_COMPOSE) up -d xkms-server 2>/dev/null || true; \
		echo "$(CYAN)$(BOLD)→ Waiting for xkms-server...$(RESET)"; \
		sleep 5; \
		echo "$(CYAN)$(BOLD)→ Running in devcontainer: $(2)$(RESET)"; \
		$(DOCKER_COMPOSE) exec -T devcontainer bash -c "cd /workspace && \
			echo 'Waiting for Unix socket...'; \
			for i in 1 2 3 4 5 6 7 8 9 10; do [ -S /var/run/xkms/xkms.sock ] && break; sleep 2; done; \
			echo 'Waiting for gRPC port...'; \
			for i in 1 2 3 4 5 6 7 8 9 10; do nc -z xkms-server 9443 2>/dev/null && break; sleep 2; done; \
			$(1)"; \
	fi
endef

.PHONY: integration-test-fido2
## integration-test-fido2: Run all FIDO2 integration tests (runs in devcontainer)
integration-test-fido2:
	$(call run_in_devcontainer,mkdir -p build/bin && CGO_ENABLED=0 $(GO) build -buildvcs=false -o build/bin/xkmsctl ./cmd/xkmsctl && $(GO) test -v -tags='integration$(comma)fido2' ./test/integration/fido2/... -timeout 10m,integration-test-fido2)

.PHONY: integration-test-fido2-cli
## integration-test-fido2-cli: Run FIDO2 CLI command tests (runs in devcontainer)
integration-test-fido2-cli:
	$(call run_in_devcontainer,mkdir -p build/bin && CGO_ENABLED=0 $(GO) build -buildvcs=false -o build/bin/xkmsctl ./cmd/xkmsctl && $(GO) test -v -tags='integration$(comma)fido2' ./test/integration/fido2/... -run 'CLI' -timeout 10m,integration-test-fido2-cli)

.PHONY: integration-test-fido2-webauthn
## integration-test-fido2-webauthn: Run FIDO2 WebAuthn server integration tests (runs in devcontainer)
integration-test-fido2-webauthn:
	$(call run_in_devcontainer,mkdir -p build/bin && CGO_ENABLED=0 $(GO) build -buildvcs=false -o build/bin/xkmsctl ./cmd/xkmsctl && $(GO) test -v -tags='integration$(comma)fido2$(comma)webauthn' ./test/integration/fido2/... -run 'WebAuthn' -timeout 10m,integration-test-fido2-webauthn)

.PHONY: integration-test-fido2-multiprotocol
## integration-test-fido2-multiprotocol: Run FIDO2 multi-protocol tests with virtual device (runs in devcontainer)
integration-test-fido2-multiprotocol:
	$(call run_in_devcontainer,$(GO) build -o build/bin/xkmsctl ./cmd/xkmsctl && FIDO2_USE_VIRTUAL=true $(GO) test -v -tags='integration$(comma)fido2' ./test/integration/fido2/... -run 'MultiProtocol' -timeout 15m,integration-test-fido2-multiprotocol)

.PHONY: integration-test-uhid
## integration-test-uhid: Run UHID package integration tests (runs in devcontainer with /dev/uhid access)
## Note: Tests require root access to /dev/uhid, so run with sudo using full go path
integration-test-uhid:
	$(call run_in_devcontainer,cd xkey && sudo /usr/local/go/bin/go test -v -tags='integration$(comma)linux' ./test/integration/uhid/... -timeout 5m,integration-test-uhid)

.PHONY: integration-test-xkey-fido2
## integration-test-xkey-fido2: Run xkey FIDO2 integration tests (runs in devcontainer with /dev/uhid access)
## Note: Tests require root access to /dev/uhid, so run with sudo using full go path
integration-test-xkey-fido2:
	$(call run_in_devcontainer,cd xkey && sudo /usr/local/go/bin/go test -v -tags='integration$(comma)linux' ./test/integration/... -timeout 5m,integration-test-xkey-fido2)

.PHONY: integration-test-xkey-webauthn
## integration-test-xkey-webauthn: Run Playwright browser tests against webauthn.io (Docker)
## Tests use Chrome CDP virtual authenticator to validate full WebAuthn registration + authentication flow
integration-test-xkey-webauthn:
	@echo "$(CYAN)$(BOLD)→ Running xkey Playwright WebAuthn integration tests...$(RESET)"
	@cd xkey/test/integration/webauthn && docker compose down -v >/dev/null 2>&1 || true
	@cd xkey/test/integration/webauthn && (docker compose run --rm webauthn-test; EXIT_CODE=$$?; docker compose down -v; exit $$EXIT_CODE)
	@echo "$(GREEN)✓ xkey Playwright WebAuthn integration tests complete$(RESET)"

.PHONY: integration-test-xkey-backends
## integration-test-xkey-backends: Run FIDO2 backend integration tests (software + TPM2 key backends)
integration-test-xkey-backends:
	$(call run_in_devcontainer,cd xkey && $(GO) test -v -tags='integration$(comma)linux' -run 'TestWebAuthnFlow' ./test/integration -timeout 5m,integration-test-xkey-backends)

.PHONY: integration-test-xkey-oidc
## integration-test-xkey-oidc: Run OIDC integration tests with ORY Hydra (Docker)
## Tests use a real ORY Hydra OIDC server to validate provider discovery, PKCE, and token flows
integration-test-xkey-oidc:
	@echo "$(CYAN)$(BOLD)→ Running xkey OIDC integration tests...$(RESET)"
	@cd xkey/test/integration/oidc && docker compose down -v >/dev/null 2>&1 || true
	@cd xkey/test/integration/oidc && (docker compose run --rm test-runner; EXIT_CODE=$$?; docker compose down -v; exit $$EXIT_CODE)
	@echo "$(GREEN)✓ xkey OIDC integration tests complete$(RESET)"

.PHONY: integration-test-xkey-piv
## integration-test-xkey-piv: Run PIV certificate storage integration tests
## Tests PIV certificate operations with file-based storage backend (no hardware required)
integration-test-xkey-piv:
	@echo "$(CYAN)$(BOLD)→ Running xkey PIV integration tests...$(RESET)"
	$(call run_in_devcontainer,cd xkey && $(GO) test -v -tags='integration' ./test/integration/piv/... -timeout 5m,integration-test-xkey-piv)
	@echo "$(GREEN)✓ xkey PIV integration tests complete$(RESET)"

.PHONY: integration-test-xkey-oath
## integration-test-xkey-oath: Run OATH (TOTP/HOTP) integration tests
## Tests OTP generation and validation with RFC 4226/6238 compliance verification
integration-test-xkey-oath:
	@echo "$(CYAN)$(BOLD)→ Running xkey OATH integration tests...$(RESET)"
	$(call run_in_devcontainer,cd xkey && $(GO) test -v -tags='integration' ./test/integration/oath/... -timeout 5m,integration-test-xkey-oath)
	@echo "$(GREEN)✓ xkey OATH integration tests complete$(RESET)"

.PHONY: integration-test-xkey-password
## integration-test-xkey-password: Run static password CLI integration tests
integration-test-xkey-password:
	$(call run_in_devcontainer,cd xkey && $(GO) test -v -tags='integration' ./test/integration/password/... -timeout 5m,integration-test-xkey-password)

.PHONY: integration-test-xkey-touch
## integration-test-xkey-touch: Run touch CLI integration tests
integration-test-xkey-touch:
	$(call run_in_devcontainer,cd xkey && $(GO) test -v -tags='integration' ./test/integration/touch/... -timeout 5m,integration-test-xkey-touch)

.PHONY: integration-test-xkey-ssh
## integration-test-xkey-ssh: Run SSH agent and key management integration tests
## Tests standalone mode and xkmsd server modes (Unix socket, gRPC)
integration-test-xkey-ssh:
	@if [ -f "/.dockerenv" ] || [ -n "$$DEVCONTAINER" ]; then \
		echo "$(CYAN)$(BOLD)→ Rebuilding xkms-server for SSH tests...$(RESET)"; \
		$(DOCKER_COMPOSE) build xkms-server; \
		echo "$(CYAN)$(BOLD)→ Starting xkms-server...$(RESET)"; \
		$(DOCKER_COMPOSE) up -d xkms-server; \
		echo "$(CYAN)$(BOLD)→ Waiting for xkms-server to be ready...$(RESET)"; \
		for i in 1 2 3 4 5 6 7 8 9 10; do \
			if [ -S /var/run/xkms/xkms.sock ]; then \
				echo "$(GREEN)✓ Unix socket ready$(RESET)"; \
				break; \
			fi; \
			echo "  Waiting for socket... ($$i/10)"; \
			sleep 2; \
		done; \
		echo "$(CYAN)$(BOLD)→ Running SSH integration tests...$(RESET)"; \
		cd xkey && $(GO) test -v -tags='integration' ./test/integration/ssh/... -timeout 5m; \
	else \
		echo "$(CYAN)$(BOLD)→ Starting devcontainer...$(RESET)"; \
		$(DOCKER_COMPOSE) up -d devcontainer 2>/dev/null || true; \
		echo "$(CYAN)$(BOLD)→ Rebuilding xkms-server...$(RESET)"; \
		$(DOCKER_COMPOSE) build xkms-server; \
		echo "$(CYAN)$(BOLD)→ Starting xkms-server...$(RESET)"; \
		$(DOCKER_COMPOSE) up -d xkms-server; \
		echo "$(CYAN)$(BOLD)→ Waiting for xkms-server...$(RESET)"; \
		sleep 5; \
		echo "$(CYAN)$(BOLD)→ Running in devcontainer: integration-test-xkey-ssh$(RESET)"; \
		$(DOCKER_COMPOSE) exec -T devcontainer bash -c "cd /workspace && for i in 1 2 3 4 5 6 7 8 9 10; do [ -S /var/run/xkms/xkms.sock ] && break; echo 'Waiting for socket... ('$$i'/10)'; sleep 2; done && cd xkey && $(GO) test -v -tags='integration' ./test/integration/ssh/... -timeout 5m"; \
	fi

.PHONY: integration-test-xkey-ctap
## integration-test-xkey-ctap: Run FIDO2 CTAP protocol integration tests (MakeCredential, GetAssertion, etc.)
## Tests the full CTAP2 protocol through the UHID virtual device
integration-test-xkey-ctap:
	$(call run_in_devcontainer,cd xkey && sudo /usr/local/go/bin/go test -v -tags='integration$(comma)linux' ./test/integration/fido2/... -timeout 10m,integration-test-xkey-ctap)

.PHONY: integration-test-xkey-luks
## integration-test-xkey-luks: Run LUKS encrypted storage integration tests (requires root for cryptsetup)
integration-test-xkey-luks:
	$(call run_in_devcontainer,mkdir -p build/bin && cd xkey && /usr/local/go/bin/go build -buildvcs=false -tags='ble$(comma)production$(comma)codec_json$(comma)pkcs11$(comma)webkit2_41' -o ../build/bin/xkey ./cmd/xkey && sudo /usr/local/go/bin/go test -v -tags='integration$(comma)linux$(comma)codec_json' ./test/integration/luks/... -timeout 10m,integration-test-xkey-luks)

.PHONY: integration-test-xkey
## integration-test-xkey: Run all xkey integration tests (FIDO2, CTAP, OIDC, PIV, OATH, Password, Touch, SSH, LUKS)
integration-test-xkey: integration-test-xkey-backends integration-test-xkey-ctap integration-test-xkey-piv integration-test-xkey-oath integration-test-xkey-password integration-test-xkey-touch integration-test-xkey-ssh integration-test-xkey-luks
	@echo "$(GREEN)✓ All xkey integration tests complete$(RESET)"

.PHONY: coverage-uhid-integration
## coverage-uhid-integration: Generate UHID integration test coverage report
## Note: Tests require root access to /dev/uhid, so run with sudo using full go path
coverage-uhid-integration:
	@echo "$(CYAN)$(BOLD)→ Generating UHID integration coverage report...$(RESET)"
	$(call run_in_devcontainer,cd xkey && sudo /usr/local/go/bin/go test -v -tags='integration$(comma)linux' -coverprofile=coverage-uhid-integration.out -covermode=atomic ./test/integration/uhid/... ./pkg/uhid/... && /usr/local/go/bin/go tool cover -func=coverage-uhid-integration.out | tail -1,coverage-uhid-integration)
	@echo "$(GREEN)✓ UHID integration coverage report generated$(RESET)"

.PHONY: coverage-xkey-integration
## coverage-xkey-integration: Generate xkey integration test coverage report
## Note: Tests require root access to /dev/uhid, so run with sudo using full go path
coverage-xkey-integration:
	@echo "$(CYAN)$(BOLD)→ Generating xkey integration coverage report...$(RESET)"
	$(call run_in_devcontainer,cd xkey && sudo /usr/local/go/bin/go test -v -tags='integration$(comma)linux' -coverprofile=coverage-xkey-integration.out -covermode=atomic -coverpkg=./cmd/xkey/...$(comma)./pkg/uhid/... ./test/integration/... ./cmd/xkey/... && /usr/local/go/bin/go tool cover -func=coverage-xkey-integration.out | tail -1,coverage-xkey-integration)
	@echo "$(GREEN)✓ xkey integration coverage report generated$(RESET)"

.PHONY: coverage-fido2
## coverage-fido2: Generate FIDO2 integration test coverage report
coverage-fido2:
	@echo "$(CYAN)$(BOLD)→ Generating FIDO2 coverage report...$(RESET)"
	@$(GOTEST) -v -tags='integration,fido2,codec_cbor,codec_json,codec_msgpack' -coverprofile=coverage-fido2.out ./test/integration/fido2/...
	@$(GO) tool cover -html=coverage-fido2.out -o coverage-fido2.html
	@echo "$(GREEN)✓ FIDO2 coverage report generated: coverage-fido2.html$(RESET)"

.PHONY: integration-test-cli
## integration-test-cli: Run CLI integration tests across all protocols (Unix, REST, gRPC, QUIC)
integration-test-cli:
	@echo "$(CYAN)$(BOLD)→ Running CLI integration tests...$(RESET)"
	@echo "$(CYAN)  Testing all protocols: Unix, REST, gRPC, QUIC$(RESET)"
	@echo "$(CYAN)  Stopping devcontainer to free port 8443...$(RESET)"
	@$(DOCKER_COMPOSE) down >/dev/null 2>&1 || true
	@test -d $(API_TEST_DIR) || (echo "$(RED)ERROR: API test directory not found: $(API_TEST_DIR)$(RESET)" && exit 1)
	@cd $(API_TEST_DIR) && docker compose down -v >/dev/null 2>&1 || true
	@cd $(API_TEST_DIR) && docker compose build
	@cd $(API_TEST_DIR) && (docker compose run --rm integration-tests; EXIT_CODE=$$?; docker compose down -v; exit $$EXIT_CODE)
	@echo "$(GREEN)✓ CLI integration tests complete$(RESET)"

.PHONY: integration-test-cli-local
## integration-test-cli-local: Run CLI integration tests locally (runs in devcontainer)
integration-test-cli-local:
	$(call run_in_devcontainer,$(GO) test -v -tags='integration$(comma)frost' ./test/integration/api/... -timeout 15m,integration-test-cli-local)

.PHONY: integration-test-signing
## integration-test-signing: Run signing package integration tests (runs in devcontainer)
integration-test-signing:
	$(call run_in_devcontainer,$(GO) test -v -tags=integration ./test/integration/signing/... -timeout 5m,integration-test-signing)

.PHONY: integration-test-opaque
## integration-test-opaque: Run opaque key package integration tests (runs in devcontainer)
integration-test-opaque:
	$(call run_in_devcontainer,$(GO) test -v -tags=integration ./test/integration/opaque/... -timeout 5m,integration-test-opaque)

.PHONY: integration-test-metrics
## integration-test-metrics: Run metrics package integration tests (runs in devcontainer)
integration-test-metrics:
	$(call run_in_devcontainer,$(GO) test -v -tags=integration ./test/integration/metrics/... -timeout 5m,integration-test-metrics)

.PHONY: integration-test-health
## integration-test-health: Run health check package integration tests (runs in devcontainer)
integration-test-health:
	$(call run_in_devcontainer,$(GO) test -v -tags=integration ./test/integration/health/... -timeout 5m,integration-test-health)

.PHONY: integration-test-ratelimit
## integration-test-ratelimit: Run rate limit package integration tests (runs in devcontainer)
integration-test-ratelimit:
	$(call run_in_devcontainer,$(GO) test -v -tags=integration ./test/integration/ratelimit/... -timeout 5m,integration-test-ratelimit)

.PHONY: integration-test-crypto-rand
## integration-test-crypto-rand: Run crypto/rand package integration tests (runs in devcontainer)
integration-test-crypto-rand:
	$(call run_in_devcontainer,$(GO) test -v -tags=integration ./test/integration/crypto/... -run '.*Rand.*' -timeout 5m,integration-test-crypto-rand)

.PHONY: integration-test-rand-hardware
## integration-test-rand-hardware: Run crypto/rand hardware integration tests (runs in devcontainer with SWTPM + SoftHSM)
integration-test-rand-hardware:
	$(call run_in_devcontainer,$(GO) test -v -tags=integration ./test/integration/crypto/... -run 'TestRand.*Hardware.*' -timeout 5m,integration-test-rand-hardware)

.PHONY: integration-test-pkcs11-nitrokey
## integration-test-pkcs11-nitrokey: Run PKCS#11 Nitrokey HSM integration tests (requires physical Nitrokey HSM)
integration-test-pkcs11-nitrokey:
	@echo "$(CYAN)$(BOLD)→ Running PKCS#11 Nitrokey HSM integration tests...$(RESET)"
	@echo "$(YELLOW)Note: This requires a physical Nitrokey HSM device$(RESET)"
	@echo "$(YELLOW)Default PKCS#11 library: /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so$(RESET)"
	@echo "$(YELLOW)Default token label: go-xkms-test (UserPIN)$(RESET)"
	@echo "$(YELLOW)Default PIN: 648219$(RESET)"
	@$(GO) test -v -tags='integration,nitrokey,pkcs11' ./test/integration/pkcs11/... -run 'TestNitrokeyHSM'
	@echo "$(GREEN)✓ PKCS#11 Nitrokey HSM integration tests complete$(RESET)"

.PHONY: integration-test-nitrokey-all
## integration-test-nitrokey-all: Run ALL Nitrokey HSM integration tests
integration-test-nitrokey-all: integration-test-pkcs11-nitrokey
	@echo "$(GREEN)$(BOLD)✓ All Nitrokey HSM integration tests complete!$(RESET)"

.PHONY: integration-test-rand-all
## integration-test-rand-all: Run ALL crypto/rand integration tests (software, hardware)
integration-test-rand-all: integration-test-crypto-rand integration-test-rand-hardware
	@echo "$(GREEN)$(BOLD)✓ All crypto/rand integration tests complete!$(RESET)"

.PHONY: integration-test-crypto-wrapping
## integration-test-crypto-wrapping: Run crypto/wrapping package integration tests (runs in devcontainer)
integration-test-crypto-wrapping:
	$(call run_in_devcontainer,$(GO) test -v -tags=integration ./test/integration/crypto/... -run '.*Wrap.*' -timeout 5m,integration-test-crypto-wrapping)

.PHONY: integration-test-utils
## integration-test-utils: Run all utility package integration tests
integration-test-utils: integration-test-signing integration-test-opaque integration-test-metrics integration-test-health integration-test-ratelimit integration-test-crypto-rand integration-test-crypto-wrapping
	@echo "$(GREEN)$(BOLD)✓ All utility package integration tests complete!$(RESET)"

# ==============================================================================
# Cloud Integration Tests (Real Cloud Services)
# ==============================================================================
# These tests connect to REAL cloud provider services and will create resources
# that cost money. Requires valid credentials and environment variables.
#
# Prerequisites:
#   AWS:   AWS CLI configured, AWS_REGION set (optional)
#   GCP:   gcloud CLI configured, GCP_PROJECT_ID, GCP_LOCATION, GCP_KEYRING set
#   Azure: Azure CLI configured, AZURE_KEYVAULT_URI set
#
# Warning: These tests will incur cloud provider costs!
# ==============================================================================

.PHONY: integration-test-cloud-aws
## integration-test-cloud-aws: Run AWS KMS integration tests against REAL AWS service (costs money!)
integration-test-cloud-aws:
	@echo "$(YELLOW)$(BOLD)⚠ WARNING: Testing against REAL AWS KMS - will incur costs!$(RESET)"
	@echo "$(CYAN)$(BOLD)→ Running AWS KMS cloud integration tests...$(RESET)"
	@$(GO) test -tags="cloud_integration awskms" -v ./test/integration/awskms/...
	@echo "$(GREEN)✓ AWS KMS cloud integration tests complete$(RESET)"

.PHONY: integration-test-cloud-gcp
## integration-test-cloud-gcp: Run GCP KMS integration tests against REAL GCP service (costs money!)
integration-test-cloud-gcp:
	@echo "$(YELLOW)$(BOLD)⚠ WARNING: Testing against REAL GCP KMS - will incur costs!$(RESET)"
	@echo "$(CYAN)$(BOLD)→ Running GCP KMS cloud integration tests...$(RESET)"
	@if [ -z "$$GCP_PROJECT_ID" ]; then \
		echo "$(RED)ERROR: GCP_PROJECT_ID not set$(RESET)"; \
		echo "Run: export GCP_PROJECT_ID=your-project-id"; \
		exit 1; \
	fi
	@$(GO) test -tags="cloud_integration gcpkms" -v ./test/integration/gcpkms/...
	@echo "$(GREEN)✓ GCP KMS cloud integration tests complete$(RESET)"

.PHONY: integration-test-cloud-azure
## integration-test-cloud-azure: Run Azure Key Vault integration tests against REAL Azure service (costs money!)
integration-test-cloud-azure:
	@echo "$(YELLOW)$(BOLD)⚠ WARNING: Testing against REAL Azure Key Vault - will incur costs!$(RESET)"
	@echo "$(CYAN)$(BOLD)→ Running Azure Key Vault cloud integration tests...$(RESET)"
	@if [ -z "$$AZURE_KEYVAULT_URI" ]; then \
		echo "$(RED)ERROR: AZURE_KEYVAULT_URI not set$(RESET)"; \
		echo "Run: export AZURE_KEYVAULT_URI=https://your-vault.vault.azure.net/"; \
		exit 1; \
	fi
	@$(GO) test -tags="cloud_integration azurekv" -v ./test/integration/azurekv/...
	@echo "$(GREEN)✓ Azure Key Vault cloud integration tests complete$(RESET)"

.PHONY: integration-test-cloud-all
## integration-test-cloud-all: Run ALL cloud integration tests against REAL cloud services (costs money!)
integration-test-cloud-all:
	@echo "$(YELLOW)$(BOLD)⚠ WARNING: Testing against ALL REAL cloud services - will incur costs!$(RESET)"
	@echo "$(CYAN)$(BOLD)→ Running all cloud integration tests...$(RESET)"
	@$(MAKE) integration-test-cloud-aws
	@$(MAKE) integration-test-cloud-gcp
	@$(MAKE) integration-test-cloud-azure
	@echo "$(GREEN)✓ All cloud integration tests complete$(RESET)"

# ==============================================================================
# Package-Specific Coverage Reports
# ==============================================================================

.PHONY: coverage-awskms
## coverage-awskms: Generate AWS KMS coverage report
coverage-awskms:
	@echo "Stopping any running emulators..."
	@$(MAKE) emulator-stop 2>/dev/null || true
	@echo "Starting fresh emulators..."
	@$(MAKE) emulator-start
	@mkdir -p $(COVERAGE_DIR)
	@AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1 LOCALSTACK_ENDPOINT=http://localhost:4566 \
		$(GO) test -v -tags="integration awskms" -coverprofile=$(COVERAGE_DIR)/awskms.out -covermode=atomic \
		./test/integration/awskms/... ./pkg/backend/awskms/... || ($(MAKE) emulator-stop && exit 1)
	@$(MAKE) emulator-stop
	@$(GO) tool cover -html=$(COVERAGE_DIR)/awskms.out -o $(COVERAGE_DIR)/awskms.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/awskms.out | grep total

.PHONY: coverage-gcpkms
## coverage-gcpkms: Generate GCP KMS coverage report (mock)
coverage-gcpkms:
	@mkdir -p $(COVERAGE_DIR)
	@$(GO) test -v -tags="integration gcpkms" -coverprofile=$(COVERAGE_DIR)/gcpkms.out -covermode=atomic \
		./test/integration/gcpkms/... ./pkg/backend/gcpkms/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/gcpkms.out -o $(COVERAGE_DIR)/gcpkms.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/gcpkms.out | grep total

.PHONY: coverage-wrapping
## coverage-wrapping: Generate key wrapping cryptographic primitives coverage report
coverage-wrapping:
	@mkdir -p $(COVERAGE_DIR)
	@$(GO) test -v -coverprofile=$(COVERAGE_DIR)/wrapping.out -covermode=atomic ./pkg/crypto/wrapping/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/wrapping.out -o $(COVERAGE_DIR)/wrapping.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/wrapping.out | grep total

.PHONY: coverage-jwk
## coverage-jwk: Generate JWK package coverage report
coverage-jwk:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating JWK coverage report...$(RESET)"
	@$(GO) test -v -coverprofile=$(COVERAGE_DIR)/jwk.out -covermode=atomic ./pkg/encoding/jwk/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/jwk.out -o $(COVERAGE_DIR)/jwk.html
	@echo "$(GREEN)✓ JWK coverage report generated$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/jwk.out | grep total

.PHONY: coverage-jwt
## coverage-jwt: Generate JWT package coverage report
coverage-jwt:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating JWT coverage report...$(RESET)"
	@$(GO) test -v -coverprofile=$(COVERAGE_DIR)/jwt.out -covermode=atomic ./pkg/encoding/jwt/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/jwt.out -o $(COVERAGE_DIR)/jwt.html
	@echo "$(GREEN)✓ JWT coverage report generated$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/jwt.out | grep total

.PHONY: coverage-jwe
## coverage-jwe: Generate JWE package coverage report
coverage-jwe:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating JWE coverage report...$(RESET)"
	@$(GO) test -v -coverprofile=$(COVERAGE_DIR)/jwe.out -covermode=atomic ./pkg/encoding/jwe/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/jwe.out -o $(COVERAGE_DIR)/jwe.html
	@echo "$(GREEN)✓ JWE coverage report generated$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/jwe.out | grep total

.PHONY: coverage-ecdh
## coverage-ecdh: Generate ECDH package coverage report
coverage-ecdh:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating ECDH coverage report...$(RESET)"
	@$(GO) test -v -coverprofile=$(COVERAGE_DIR)/ecdh.out -covermode=atomic ./pkg/crypto/ecdh/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/ecdh.out -o $(COVERAGE_DIR)/ecdh.html
	@echo "$(GREEN)✓ ECDH coverage report generated$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/ecdh.out | grep total

.PHONY: coverage-ecies
## coverage-ecies: Generate ECIES package coverage report
coverage-ecies:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating ECIES coverage report...$(RESET)"
	@$(GO) test -v -coverprofile=$(COVERAGE_DIR)/ecies.out -covermode=atomic ./pkg/crypto/ecies/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/ecies.out -o $(COVERAGE_DIR)/ecies.html
	@echo "$(GREEN)✓ ECIES coverage report generated$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/ecies.out | grep total

.PHONY: coverage-x25519
## coverage-x25519: Generate X25519 package coverage report
coverage-x25519:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating X25519 coverage report...$(RESET)"
	@$(GO) test -v -coverprofile=$(COVERAGE_DIR)/x25519.out -covermode=atomic ./pkg/crypto/x25519/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/x25519.out -o $(COVERAGE_DIR)/x25519.html
	@echo "$(GREEN)✓ X25519 coverage report generated$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/x25519.out | grep total

.PHONY: coverage-chacha20poly1305
## coverage-chacha20poly1305: Generate ChaCha20-Poly1305 package coverage report
coverage-chacha20poly1305:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating ChaCha20-Poly1305 coverage report...$(RESET)"
	@$(GO) test -v -coverprofile=$(COVERAGE_DIR)/chacha20poly1305.out -covermode=atomic ./pkg/crypto/chacha20poly1305/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/chacha20poly1305.out -o $(COVERAGE_DIR)/chacha20poly1305.html
	@echo "$(GREEN)✓ ChaCha20-Poly1305 coverage report generated$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/chacha20poly1305.out | grep total

.PHONY: coverage-importexport
## coverage-importexport: Generate combined import/export coverage report for all backends
coverage-importexport:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating import/export coverage report...$(RESET)"
	@$(GO) test -v -coverprofile=$(COVERAGE_DIR)/wrapping.out -covermode=atomic ./pkg/crypto/wrapping/...
	@$(GO) test -v -coverprofile=$(COVERAGE_DIR)/software_import.out -covermode=atomic ./pkg/backend/software/... -run "Test.*Import|Test.*Export"
	@$(GO) test -v -coverprofile=$(COVERAGE_DIR)/symmetric_import.out -covermode=atomic ./pkg/keyprovider/symmetric/... -run "Test.*Import|Test.*Export"
	@$(GO) test -tags= -v -coverprofile=$(COVERAGE_DIR)/tpm2_import.out -covermode=atomic ./pkg/tpm2/... -run "Test.*Import|Test.*Export"
	@echo "$(GREEN)✓ Import/export coverage reports generated$(RESET)"
	@echo "$(CYAN)Wrapping:$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/wrapping.out | grep total
	@echo "$(CYAN)Software:$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/software_import.out | grep total
	@echo "$(CYAN)AES:$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/aes_import.out | grep total
	@echo "$(CYAN)TPM2:$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/tpm2_import.out | grep total

.PHONY: coverage-azurekv
## coverage-azurekv: Generate Azure Key Vault coverage report
coverage-azurekv:
	@echo "Stopping any running emulators..."
	@$(MAKE) emulator-stop 2>/dev/null || true
	@echo "Starting fresh emulators..."
	@$(MAKE) emulator-start
	@mkdir -p $(COVERAGE_DIR)
	@AZURE_KEYVAULT_ENDPOINT=https://localhost:4997 \
		$(GO) test -v -tags="integration azurekv" -coverprofile=$(COVERAGE_DIR)/azurekv.out -covermode=atomic \
		./test/integration/azurekv/... ./pkg/backend/azurekv/... || ($(MAKE) emulator-stop && exit 1)
	@$(MAKE) emulator-stop
	@$(GO) tool cover -html=$(COVERAGE_DIR)/azurekv.out -o $(COVERAGE_DIR)/azurekv.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/azurekv.out | grep total

.PHONY: coverage-pkcs11
## coverage-pkcs11: Generate PKCS11 coverage report (requires SoftHSM)
coverage-pkcs11:
	@mkdir -p $(COVERAGE_DIR)
	@echo "Generating PKCS11 coverage report (requires SoftHSM installed)..."
	@$(GO) test -v -tags="integration pkcs11" -coverprofile=$(COVERAGE_DIR)/pkcs11.out -covermode=atomic \
		./test/integration/pkcs11/... ./pkg/backend/pkcs11/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/pkcs11.out -o $(COVERAGE_DIR)/pkcs11.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/pkcs11.out | grep total

.PHONY: coverage-tpm2
## coverage-tpm2: Generate TPM2 coverage report (requires TPM device or simulator)
coverage-tpm2:
	@mkdir -p $(COVERAGE_DIR)
	@echo "Generating TPM2 coverage report (requires TPM device at /dev/tpmrm0)..."
	@$(GO) test -v -tags="integration codec_cbor codec_json codec_msgpack" -coverprofile=$(COVERAGE_DIR)/tpm2.out -covermode=atomic \
		./test/integration/tpm2/... ./pkg/tpm2/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/tpm2.out -o $(COVERAGE_DIR)/tpm2.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/tpm2.out | grep total


# ==============================================================================
# Version Management Targets
# ==============================================================================

.PHONY: version
## version: Display current version
version:
	@echo "$(BOLD)$(BLUE)Current version: $(VERSION)$(RESET)"

.PHONY: bump-major
## bump-major: Increment major version (X.0.0)
bump-major:
	@echo "$(CYAN)$(BOLD)→ Bumping major version...$(RESET)"
	@CURRENT=$$(cat VERSION); \
	MAJOR=$$(echo $$CURRENT | cut -d. -f1); \
	PRERELEASE=$$(echo $$CURRENT | grep -oP '(?<=-)[^-]+$$' || echo ""); \
	NEW_MAJOR=$$((MAJOR + 1)); \
	if [ -n "$$PRERELEASE" ]; then \
		NEW_VERSION="$$NEW_MAJOR.0.0-$$PRERELEASE"; \
	else \
		NEW_VERSION="$$NEW_MAJOR.0.0"; \
	fi; \
	echo $$NEW_VERSION > VERSION; \
	echo "$(GREEN)✓ Version bumped: $$CURRENT -> $$NEW_VERSION$(RESET)"

.PHONY: bump-minor
## bump-minor: Increment minor version (x.Y.0)
bump-minor:
	@echo "$(CYAN)$(BOLD)→ Bumping minor version...$(RESET)"
	@CURRENT=$$(cat VERSION); \
	MAJOR=$$(echo $$CURRENT | cut -d. -f1); \
	MINOR=$$(echo $$CURRENT | cut -d. -f2); \
	PRERELEASE=$$(echo $$CURRENT | grep -oP '(?<=-)[^-]+$$' || echo ""); \
	NEW_MINOR=$$((MINOR + 1)); \
	if [ -n "$$PRERELEASE" ]; then \
		NEW_VERSION="$$MAJOR.$$NEW_MINOR.0-$$PRERELEASE"; \
	else \
		NEW_VERSION="$$MAJOR.$$NEW_MINOR.0"; \
	fi; \
	echo $$NEW_VERSION > VERSION; \
	echo "$(GREEN)✓ Version bumped: $$CURRENT -> $$NEW_VERSION$(RESET)"

.PHONY: bump-patch
## bump-patch: Increment patch version (x.y.Z)
bump-patch:
	@echo "$(CYAN)$(BOLD)→ Bumping patch version...$(RESET)"
	@CURRENT=$$(cat VERSION); \
	MAJOR=$$(echo $$CURRENT | cut -d. -f1); \
	MINOR=$$(echo $$CURRENT | cut -d. -f2); \
	PATCH=$$(echo $$CURRENT | cut -d. -f3 | cut -d- -f1); \
	PRERELEASE=$$(echo $$CURRENT | grep -oP '(?<=-)[^-]+$$' || echo ""); \
	NEW_PATCH=$$((PATCH + 1)); \
	if [ -n "$$PRERELEASE" ]; then \
		NEW_VERSION="$$MAJOR.$$MINOR.$$NEW_PATCH-$$PRERELEASE"; \
	else \
		NEW_VERSION="$$MAJOR.$$MINOR.$$NEW_PATCH"; \
	fi; \
	echo $$NEW_VERSION > VERSION; \
	echo "$(GREEN)✓ Version bumped: $$CURRENT -> $$NEW_VERSION$(RESET)"

.PHONY: release-version
## release-version: Remove pre-release identifier from VERSION file
release-version:
	@echo "$(CYAN)$(BOLD)→ Creating release version...$(RESET)"
	@CURRENT=$$(cat VERSION); \
	BASE=$$(echo $$CURRENT | cut -d- -f1); \
	if [ "$$CURRENT" = "$$BASE" ]; then \
		echo "$(YELLOW)⚠ Version $$CURRENT is already a release version$(RESET)"; \
	else \
		echo $$BASE > VERSION; \
		echo "$(GREEN)✓ Release version created: $$CURRENT -> $$BASE$(RESET)"; \
	fi

.PHONY: release-docker
## release-docker: Build and tag Docker images for release
release-docker:
	@echo "$(CYAN)$(BOLD)→ Building release Docker images (version $(VERSION))...$(RESET)"
	@echo "$(CYAN)  Git Commit: $(GIT_COMMIT)$(RESET)"
	@echo "$(CYAN)  Build Date: $(BUILD_DATE)$(RESET)"
	@$(MAKE) --no-print-directory docker-build-all
	@echo "$(GREEN)$(BOLD)✓ All release Docker images built successfully!$(RESET)"
	@echo "$(CYAN)Docker images:$(RESET)"
	@docker images | grep $(PROJECT_NAME) | grep -E "($(VERSION)|latest)"

.PHONY: release
## release: Create GitHub release with versioned shared library
release: lib release-binaries
	@echo "$(CYAN)$(BOLD)→ Creating GitHub release v$(VERSION)...$(RESET)"
	@if ! command -v gh >/dev/null 2>&1; then \
		echo "$(RED)✗ GitHub CLI (gh) not found. Install with:$(RESET)"; \
		echo "  - Ubuntu/Debian: sudo apt install gh"; \
		echo "  - macOS: brew install gh"; \
		echo "  - Or visit: https://cli.github.com/"; \
		exit 1; \
	fi
	@if [ ! -f "$(SHARED_LIB)" ]; then \
		echo "$(RED)✗ Shared library not found: $(SHARED_LIB)$(RESET)"; \
		echo "$(YELLOW)  Run 'make lib' first$(RESET)"; \
		exit 1; \
	fi
	@if [ ! -f "CHANGELOG.md" ]; then \
		echo "$(RED)✗ CHANGELOG.md not found$(RESET)"; \
		exit 1; \
	fi
	@echo "$(CYAN)  Extracting release notes for v$(VERSION)...$(RESET)"
	@VERSION_ESCAPED=$$(echo "$(VERSION)" | sed 's/\./\\./g'); \
	sed -n "/## \[$$VERSION_ESCAPED\]/,/^## \[/{/## \[$$VERSION_ESCAPED\]/d;/^## \[/d;p;}" CHANGELOG.md > /tmp/release-notes-$(VERSION).md || \
		(echo "$(RED)✗ Could not extract release notes for v$(VERSION)$(RESET)" && exit 1); \
	if [ ! -s /tmp/release-notes-$(VERSION).md ]; then \
		echo "$(RED)✗ No release notes found for v$(VERSION) in CHANGELOG.md$(RESET)"; \
		echo "$(YELLOW)  Please add release notes to CHANGELOG.md first$(RESET)"; \
		exit 1; \
	fi
	@echo "$(CYAN)  Creating release v$(VERSION) with all platform binaries...$(RESET)"
	@gh release create v$(VERSION) \
		$(SHARED_LIB) \
		$(BIN_DIR)/release/xkmsctl-* \
		$(BIN_DIR)/release/xkmsd-* \
		--title "go-xkms v$(VERSION)" \
		--notes-file /tmp/release-notes-$(VERSION).md
	@rm -f /tmp/release-notes-$(VERSION).md
	@echo "$(GREEN)$(BOLD)✓ GitHub release v$(VERSION) created successfully!$(RESET)"
	@echo "$(CYAN)  Release URL: $$(gh release view v$(VERSION) --json url -q .url)$(RESET)"
	@echo "$(CYAN)  Attached binaries:$(RESET)"
	@echo "$(CYAN)    - $(SHARED_LIB)$(RESET)"
	@echo "$(CYAN)    - xkmsctl (all platforms)$(RESET)"
	@echo "$(CYAN)    - xkmsd (all platforms)$(RESET)"

# ==============================================================================
# Docker Targets
# ==============================================================================

.PHONY: docker-build
## docker-build: Build Docker container for integration testing
docker-build:
	@echo "$(CYAN)$(BOLD)→ Building Docker image...$(RESET)"
	@if [ ! -f "Dockerfile" ]; then \
		echo "$(YELLOW)⚠ Dockerfile not found. Creating default Dockerfile...$(RESET)"; \
		$(MAKE) --no-print-directory create-dockerfile; \
	fi
	@docker buildx build --load -t $(DOCKER_INTEGRATION_IMAGE) -f Dockerfile .
	@echo "$(GREEN)✓ Docker image built: $(DOCKER_INTEGRATION_IMAGE)$(RESET)"

.PHONY: docker-build-server
## docker-build-server: Build Docker image for unified server
docker-build-server:
	@echo "$(CYAN)$(BOLD)→ Building unified server Docker image...$(RESET)"
	@docker buildx build --load \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(PROJECT_NAME)-server:$(VERSION) \
		-t $(PROJECT_NAME)-server:latest \
		-f Dockerfile.server .
	@echo "$(GREEN)✓ Unified server Docker image built: $(PROJECT_NAME)-server:$(VERSION)$(RESET)"

.PHONY: docker-build-rest
## docker-build-rest: Build Docker image for REST server
docker-build-rest:
	@echo "$(CYAN)$(BOLD)→ Building REST server Docker image...$(RESET)"
	@docker buildx build --load \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(PROJECT_NAME)-rest:$(VERSION) \
		-t $(PROJECT_NAME)-rest:latest \
		-f Dockerfile.rest .
	@echo "$(GREEN)✓ REST server Docker image built: $(PROJECT_NAME)-rest:$(VERSION)$(RESET)"

.PHONY: docker-build-grpc
## docker-build-grpc: Build Docker image for gRPC server
docker-build-grpc:
	@echo "$(CYAN)$(BOLD)→ Building gRPC server Docker image...$(RESET)"
	@docker buildx build --load \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(PROJECT_NAME)-grpc:$(VERSION) \
		-t $(PROJECT_NAME)-grpc:latest \
		-f Dockerfile.grpc .
	@echo "$(GREEN)✓ gRPC server Docker image built: $(PROJECT_NAME)-grpc:$(VERSION)$(RESET)"

.PHONY: docker-build-quic
## docker-build-quic: Build Docker image for QUIC server
docker-build-quic:
	@echo "$(CYAN)$(BOLD)→ Building QUIC server Docker image...$(RESET)"
	@docker buildx build --load \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(PROJECT_NAME)-quic:$(VERSION) \
		-t $(PROJECT_NAME)-quic:latest \
		-f Dockerfile.quic .
	@echo "$(GREEN)✓ QUIC server Docker image built: $(PROJECT_NAME)-quic:$(VERSION)$(RESET)"

.PHONY: docker-build-mcp
## docker-build-mcp: Build Docker image for MCP server
docker-build-mcp:
	@echo "$(CYAN)$(BOLD)→ Building MCP server Docker image...$(RESET)"
	@docker buildx build --load \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(PROJECT_NAME)-mcp:$(VERSION) \
		-t $(PROJECT_NAME)-mcp:latest \
		-f Dockerfile.mcp .
	@echo "$(GREEN)✓ MCP server Docker image built: $(PROJECT_NAME)-mcp:$(VERSION)$(RESET)"

.PHONY: docker-build-cli
## docker-build-cli: Build Docker image for CLI
docker-build-cli:
	@echo "$(CYAN)$(BOLD)→ Building CLI Docker image...$(RESET)"
	@docker buildx build --load \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(PROJECT_NAME)-cli:$(VERSION) \
		-t $(PROJECT_NAME)-cli:latest \
		-f Dockerfile.cli .
	@echo "$(GREEN)✓ CLI Docker image built: $(PROJECT_NAME)-cli:$(VERSION)$(RESET)"

.PHONY: docker-build-all
## docker-build-all: Build all Docker images (servers + CLI)
docker-build-all: docker-build-server docker-build-rest docker-build-grpc docker-build-quic docker-build-mcp docker-build-cli
	@echo "$(GREEN)$(BOLD)✓ All Docker images built successfully!$(RESET)"

.PHONY: docker-run
## docker-run: Run a new Docker container with the built image
docker-run: docker-build
	@echo "$(CYAN)$(BOLD)→ Starting Docker container...$(RESET)"
	@docker run -it --rm \
		-v $(PWD):/workspace \
		$(SIBLING_MOUNTS) \
		-w /workspace \
		--name $(DOCKER_CONTAINER) \
		$(DOCKER_INTEGRATION_IMAGE) \
		/bin/bash

.PHONY: docker-test
## docker-test: Start a new container and run make test
docker-test: docker-build
	@echo "$(CYAN)$(BOLD)→ Running tests in Docker container...$(RESET)"
	@docker run --rm \
		-v $(PWD):/workspace \
		$(SIBLING_MOUNTS) \
		-w /workspace \
		--name $(PROJECT_NAME)-test \
		$(DOCKER_INTEGRATION_IMAGE) \
		make test
	@echo "$(GREEN)$(BOLD)✓ Docker tests complete!$(RESET)"

.PHONY: docker-stop
## docker-stop: Stop running containers
docker-stop:
	@echo "$(CYAN)→ Stopping Docker containers...$(RESET)"
	@docker stop $(DOCKER_CONTAINER) 2>/dev/null || true
	@docker stop $(PROJECT_NAME)-test 2>/dev/null || true
	@docker stop $(PROJECT_NAME)-integration-test 2>/dev/null || true
	@echo "$(GREEN)✓ Containers stopped$(RESET)"

.PHONY: docker-clean
## docker-clean: Remove Docker images and containers
docker-clean: docker-stop
	@echo "$(CYAN)→ Cleaning Docker resources...$(RESET)"
	@docker rm $(DOCKER_CONTAINER) 2>/dev/null || true
	@docker rmi $(DOCKER_IMAGE) 2>/dev/null || true
	@docker rmi $(DOCKER_INTEGRATION_IMAGE) 2>/dev/null || true
	@echo "$(GREEN)✓ Docker resources cleaned$(RESET)"

.PHONY: create-dockerfile
# Create default Dockerfile if it doesn't exist
create-dockerfile:
	@echo "# Dockerfile for go-xkms integration testing" > Dockerfile
	@echo "FROM golang:1.26.1-alpine" >> Dockerfile
	@echo "" >> Dockerfile
	@echo "# Install dependencies" >> Dockerfile
	@echo "RUN apk add --no-cache \\" >> Dockerfile
	@echo "    build-base \\" >> Dockerfile
	@echo "    softhsm \\" >> Dockerfile
	@echo "    openssl \\" >> Dockerfile
	@echo "    bash \\" >> Dockerfile
	@echo "    git \\" >> Dockerfile
	@echo "    make \\" >> Dockerfile
	@echo "    bc" >> Dockerfile
	@echo "" >> Dockerfile
	@echo "# Set working directory" >> Dockerfile
	@echo "WORKDIR /workspace" >> Dockerfile
	@echo "" >> Dockerfile
	@echo "# Copy go modules" >> Dockerfile
	@echo "COPY go.mod go.sum ./" >> Dockerfile
	@echo "RUN go mod download" >> Dockerfile
	@echo "" >> Dockerfile
	@echo "# Copy source code" >> Dockerfile
	@echo "COPY . ." >> Dockerfile
	@echo "" >> Dockerfile
	@echo "# Default command" >> Dockerfile
	@echo 'CMD ["/bin/bash"]' >> Dockerfile
	@echo "$(GREEN)✓ Created Dockerfile$(RESET)"

# ==============================================================================
# Docker Compose Targets
# ==============================================================================

.PHONY: compose-up
## compose-up: Start all services with docker-compose
compose-up:
	@echo "$(CYAN)$(BOLD)→ Starting services with docker-compose...$(RESET)"
	@docker compose up -d
	@echo "$(GREEN)✓ Services started$(RESET)"

.PHONY: compose-down
## compose-down: Stop all services with docker-compose
compose-down:
	@echo "$(CYAN)→ Stopping services with docker-compose...$(RESET)"
	@docker compose down -v
	@echo "$(GREEN)✓ Services stopped$(RESET)"

.PHONY: compose-test
## compose-test: Run unit tests using docker-compose
compose-test:
	@echo "$(CYAN)$(BOLD)→ Running unit tests with docker-compose...$(RESET)"
	@docker compose run --rm unit-test
	@echo "$(GREEN)$(BOLD)✓ Tests complete!$(RESET)"

.PHONY: compose-integration
## compose-integration: Run integration tests using docker-compose
compose-integration:
	@echo "$(CYAN)$(BOLD)→ Running integration tests with docker-compose...$(RESET)"
	@docker compose run --rm integration-test
	@echo "$(GREEN)$(BOLD)✓ Integration tests complete!$(RESET)"

.PHONY: compose-dev
## compose-dev: Start interactive development shell with docker-compose
compose-dev:
	@docker compose run --rm dev

.PHONY: compose-build
## compose-build: Build docker-compose images
compose-build:
	@echo "$(CYAN)$(BOLD)→ Building docker-compose images...$(RESET)"
	@docker compose build
	@echo "$(GREEN)✓ Images built$(RESET)"

.PHONY: compose-build-swtpm
## compose-build-swtpm: Build SWTPM Docker image only
compose-build-swtpm:
	@echo "$(CYAN)$(BOLD)→ Building SWTPM image...$(RESET)"
	@docker compose build swtpm
	@echo "$(GREEN)✓ SWTPM image built$(RESET)"

.PHONY: compose-build-softhsm
## compose-build-softhsm: Build SoftHSM Docker image only
compose-build-softhsm:
	@echo "$(CYAN)$(BOLD)→ Building SoftHSM image...$(RESET)"
	@docker compose build softhsm
	@echo "$(GREEN)✓ SoftHSM image built$(RESET)"

.PHONY: compose-test-integration
## compose-test-integration: Run integration tests with test-specific config
compose-test-integration:
	@echo "$(CYAN)$(BOLD)→ Running integration tests with test configuration...$(RESET)"
	@docker compose -f docker-compose.yml -f test/docker/docker-compose.test.yml up --abort-on-container-exit
	@echo "$(GREEN)$(BOLD)✓ Integration tests complete!$(RESET)"

.PHONY: compose-logs
## compose-logs: View logs from all services
compose-logs:
	@docker compose logs -f

.PHONY: compose-logs-swtpm
## compose-logs-swtpm: View SWTPM logs
compose-logs-swtpm:
	@docker compose logs -f swtpm

.PHONY: compose-logs-softhsm
## compose-logs-softhsm: View SoftHSM logs
compose-logs-softhsm:
	@docker compose logs -f softhsm

.PHONY: compose-ps
## compose-ps: Show status of all services
compose-ps:
	@docker compose ps

.PHONY: compose-clean
## compose-clean: Clean docker-compose resources
compose-clean:
	@echo "$(CYAN)→ Cleaning docker-compose resources...$(RESET)"
	@docker compose down -v --rmi all --remove-orphans
	@echo "$(GREEN)✓ Compose resources cleaned$(RESET)"

# ==============================================================================
# Code Quality Targets
# ==============================================================================

.PHONY: fmt
## fmt: Format code with gofmt
fmt:
	@echo "$(CYAN)$(BOLD)→ Formatting code...$(RESET)"
	@$(GOFMT) -s -w .
	@echo "$(GREEN)✓ Code formatted$(RESET)"

.PHONY: fmt-check
## fmt-check: Check if code is formatted
fmt-check:
	@echo "$(CYAN)$(BOLD)→ Checking code formatting...$(RESET)"
	@UNFORMATTED=$$($(GOFMT) -l . 2>/dev/null | grep -v vendor | grep -v build || true); \
	if [ -n "$$UNFORMATTED" ]; then \
		echo "$(RED)✗ Code is not formatted. Run 'make fmt'$(RESET)"; \
		echo "$$UNFORMATTED"; \
		exit 1; \
	fi
	@echo "$(GREEN)✓ Code is properly formatted$(RESET)"

.PHONY: vet
## vet: Run go vet on the codebase
vet:
	@echo "$(CYAN)$(BOLD)→ Running go vet...$(RESET)"
	@$(GOVET) ./...
	@echo "$(GREEN)✓ Vet checks passed$(RESET)"

.PHONY: lint
## lint: Run linters (golangci-lint if available, otherwise go vet)
lint:
	@echo "$(CYAN)$(BOLD)→ Running linters...$(RESET)"
	@GOLANGCI_LINT_BIN=$$(command -v golangci-lint 2>/dev/null || echo "$$HOME/go/bin/golangci-lint"); \
	if [ -x "$$GOLANGCI_LINT_BIN" ]; then \
		if $$GOLANGCI_LINT_BIN run --timeout=5m ./...; then \
			echo "$(GREEN)✓ Linting complete$(RESET)"; \
		else \
			echo "$(RED)$(BOLD)✗ Linting failed with errors$(RESET)"; \
			exit 1; \
		fi \
	else \
		echo "$(RED)✗ golangci-lint is required but not installed$(RESET)"; \
		echo "$(YELLOW)  Install with: make install-tools$(RESET)"; \
		echo "$(YELLOW)  Or run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest$(RESET)"; \
		exit 1; \
	fi

# gosec exclusions (documented):
#   G103: unsafe calls - required for HID ioctls and protobuf generated code
#   G104: unhandled errors - false positive for hash.Write (never returns error)
#   G115: Integer overflow conversions - values are bounded by crypto/TPM specs
#   G304: File path inclusion - internal paths validated at API boundaries
#   G401: sha1.New() - required for OAEP-SHA1 and RSA-AES-KEY-WRAP-SHA1 (legacy compat)
#   G407: False positive - gcm.Seal nonce is random (io.ReadFull), not hardcoded
#   G505: crypto/sha1 import - required for PKCS standards, cert thumbprints, WebAuthn
GOSEC_EXCLUDE := G103,G104,G115,G117,G204,G302,G304,G306,G401,G402,G407,G501,G505,G703,G704,G705

.PHONY: gosec
## gosec: Run gosec security scanner (fails on HIGH/MEDIUM severity issues)
gosec:
	@echo "$(CYAN)$(BOLD)→ Running security analysis with gosec...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	@GOSEC_BIN=$$(command -v gosec 2>/dev/null || echo "$$HOME/go/bin/gosec"); \
	if [ -x "$$GOSEC_BIN" ]; then \
		$$GOSEC_BIN -exclude=$(GOSEC_EXCLUDE) -severity medium -confidence medium \
			-exclude-dir=test -exclude-dir=testdata -exclude-dir=vendor \
			-exclude-dir=xkey \
			-exclude-generated \
			-no-fail \
			-fmt=text -out=$(BUILD_DIR)/gosec-report.txt ./... ; \
		ISSUE_COUNT=$$(grep -c '^  Issues' $(BUILD_DIR)/gosec-report.txt 2>/dev/null || echo 0); \
		REAL_ISSUES=$$(grep '^  Issues' $(BUILD_DIR)/gosec-report.txt | awk '{print $$3}' 2>/dev/null || echo 0); \
		if [ "$$REAL_ISSUES" = "0" ]; then \
			echo "$(GREEN)✓ Security scan complete - no issues found$(RESET)"; \
			echo "$(CYAN)Report saved to: $(BUILD_DIR)/gosec-report.txt$(RESET)"; \
		else \
			echo "$(RED)✗ Security issues found! See $(BUILD_DIR)/gosec-report.txt$(RESET)"; \
			cat $(BUILD_DIR)/gosec-report.txt; \
			exit 1; \
		fi; \
	else \
		echo "$(YELLOW)⚠ gosec not found$(RESET)"; \
		echo "$(YELLOW)  Install with: make install-gosec$(RESET)"; \
		exit 1; \
	fi

.PHONY: vuln
## vuln: Run govulncheck to scan for known vulnerabilities
vuln:
	@echo "$(CYAN)$(BOLD)→ Running vulnerability scan with govulncheck...$(RESET)"
	@GOVULNCHECK_BIN=$$(command -v govulncheck 2>/dev/null || echo "$$HOME/go/bin/govulncheck"); \
	if [ -x "$$GOVULNCHECK_BIN" ]; then \
		$$GOVULNCHECK_BIN ./...; \
		echo "$(GREEN)✓ Vulnerability scan complete$(RESET)"; \
	else \
		echo "$(YELLOW)⚠ govulncheck not found$(RESET)"; \
		echo "$(YELLOW)  Install with: make install-govulncheck$(RESET)"; \
		exit 1; \
	fi

.PHONY: trivy
## trivy: Run Trivy vulnerability scanner on filesystem (matches GitHub CI)
trivy:
	@echo "$(CYAN)$(BOLD)→ Running Trivy vulnerability scan...$(RESET)"
	@TRIVY_BIN=$$(command -v trivy 2>/dev/null); \
	if [ -n "$$TRIVY_BIN" ]; then \
		$$TRIVY_BIN fs --severity CRITICAL,HIGH --exit-code 1 . && \
		echo "$(GREEN)✓ Trivy scan complete - no critical/high vulnerabilities found$(RESET)"; \
	else \
		echo "$(YELLOW)⚠ trivy not found - skipping (install with: make install-trivy)$(RESET)"; \
	fi

.PHONY: trivy-image
## trivy-image: Run Trivy on Docker image (same as GitHub CI)
trivy-image: docker
	@echo "$(CYAN)$(BOLD)→ Running Trivy vulnerability scan on Docker image...$(RESET)"
	@TRIVY_BIN=$$(command -v trivy 2>/dev/null); \
	if [ -n "$$TRIVY_BIN" ]; then \
		$$TRIVY_BIN image --severity CRITICAL,HIGH $(REGISTRY)/$(IMAGE_NAME):$(VERSION) && \
		echo "$(GREEN)✓ Trivy image scan complete$(RESET)"; \
	else \
		echo "$(YELLOW)⚠ trivy not found$(RESET)"; \
		echo "$(YELLOW)  Install with: make install-trivy$(RESET)"; \
		exit 1; \
	fi

.PHONY: check
## check: Run all code quality checks (fmt, vet, lint, gosec, vuln)
check: fmt vet lint gosec vuln
	@echo "$(GREEN)$(BOLD)✓ All quality checks passed!$(RESET)"

# ==============================================================================
# Tool Installation
# ==============================================================================

.PHONY: install-trivy
## install-trivy: Install Trivy vulnerability scanner
install-trivy:
	@echo "$(CYAN)$(BOLD)→ Installing trivy...$(RESET)"
	@if ! command -v trivy >/dev/null 2>&1; then \
		echo "$(CYAN)  Installing Trivy vulnerability scanner...$(RESET)"; \
		curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b $$(go env GOPATH)/bin; \
		echo "$(GREEN)  ✓ trivy installed$(RESET)"; \
	else \
		echo "$(GREEN)  ✓ trivy already installed$(RESET)"; \
	fi

.PHONY: install-govulncheck
## install-govulncheck: Install govulncheck vulnerability scanner
install-govulncheck:
	@echo "$(CYAN)$(BOLD)→ Installing govulncheck...$(RESET)"
	@if ! command -v govulncheck >/dev/null 2>&1; then \
		echo "$(CYAN)  Installing govulncheck vulnerability scanner...$(RESET)"; \
		go install golang.org/x/vuln/cmd/govulncheck@latest; \
		echo "$(GREEN)  ✓ govulncheck installed$(RESET)"; \
	else \
		echo "$(GREEN)  ✓ govulncheck already installed$(RESET)"; \
	fi

.PHONY: install-gosec
## install-gosec: Install gosec security scanner
install-gosec:
	@echo "$(CYAN)$(BOLD)→ Installing gosec...$(RESET)"
	@if ! command -v gosec >/dev/null 2>&1; then \
		echo "$(CYAN)  Installing gosec security scanner...$(RESET)"; \
		go install github.com/securego/gosec/v2/cmd/gosec@latest; \
		echo "$(GREEN)  ✓ gosec installed$(RESET)"; \
	else \
		echo "$(GREEN)  ✓ gosec already installed$(RESET)"; \
	fi

.PHONY: install-tools
## install-tools: Install development tools (golangci-lint, gosec, govulncheck, trivy, etc.)
install-tools: install-gosec install-govulncheck install-trivy
	@echo "$(CYAN)$(BOLD)→ Installing development tools...$(RESET)"
	@echo "$(CYAN)  Installing golangci-lint v2.6.2 (same as CI)...$(RESET)"
	@cd /tmp && \
		wget -q https://github.com/golangci/golangci-lint/releases/download/v2.6.2/golangci-lint-2.6.2-linux-amd64.tar.gz && \
		tar -xzf golangci-lint-2.6.2-linux-amd64.tar.gz && \
		sudo mkdir -p $(shell go env GOPATH)/bin && \
		sudo cp golangci-lint-2.6.2-linux-amd64/golangci-lint $(shell go env GOPATH)/bin/ && \
		sudo chmod +x $(shell go env GOPATH)/bin/golangci-lint && \
		sudo chown $(shell whoami):$(shell whoami) $(shell go env GOPATH)/bin/golangci-lint && \
		rm -rf golangci-lint-2.6.2-linux-amd64*
	@echo "$(GREEN)  ✓ golangci-lint v2.6.2 installed$(RESET)"
	@echo "$(GREEN)✓ Development tools installed$(RESET)"

# ==============================================================================
# Utility Targets
# ==============================================================================

.PHONY: tidy
## tidy: Tidy go.mod
tidy:
	@echo "$(CYAN)$(BOLD)→ Tidying go.mod...$(RESET)"
	@$(GOMOD) tidy
	@echo "$(GREEN)✓ go.mod tidied$(RESET)"

.PHONY: verify
## verify: Run all checks and tests before commit
verify: clean deps check test
	@echo "$(GREEN)$(BOLD)✓ Verification complete! Ready to commit.$(RESET)"

# CI Docker image name
CI_IMAGE_NAME := go-xkms-ci

.PHONY: docker-ci-build
## docker-ci-build: Build the CI Docker image with all tools
docker-ci-build:
	@echo "$(CYAN)$(BOLD)→ Building CI Docker image...$(RESET)"
	@DOCKER_BUILDKIT=0 docker build -t $(CI_IMAGE_NAME):latest -f Dockerfile.ci .
	@echo "$(GREEN)✓ CI Docker image built$(RESET)"

.PHONY: docker-ci
## docker-ci: Run full CI pipeline in Docker container (recommended)
docker-ci: docker-ci-build
	@echo "$(CYAN)$(BOLD)→ Running CI pipeline in Docker container...$(RESET)"
	@docker run --rm \
		-v $(PWD):/workspace \
		$(SIBLING_MOUNTS) \
		-w /workspace \
		$(CI_IMAGE_NAME):latest \
		make ci-local
	@echo "$(GREEN)$(BOLD)✓ CI pipeline complete!$(RESET)"

.PHONY: ci-local
## ci-local: Run CI pipeline locally (requires all tools installed)
ci-local: deps fmt-check vet lint gosec vuln trivy build-cli test race
	@echo "$(GREEN)$(BOLD)✓ CI pipeline complete!$(RESET)"

.PHONY: ci
## ci: Run CI pipeline in Docker (use ci-local for host execution)
ci: docker-ci

# ==============================================================================
# Clean Targets
# ==============================================================================

.PHONY: clean
## clean: Clean up all build artifacts and test outputs
clean:
	@echo "$(CYAN)$(BOLD)→ Cleaning build artifacts...$(RESET)"
	@$(GOCLEAN)
	@rm -rf $(BUILD_DIR)
	@rm -rf $(COVERAGE_DIR)
	@rm -f *.out *.log *.test *.prof
	@rm -f $(SHARED_LIB)
	@rm -f server cli xkms xkmsd
	@rm -f COMMIT_SUMMARY.md
	@find . -name "*.test" -type f -delete 2>/dev/null || true
	@find . -name "*.out" -type f -delete 2>/dev/null || true
	@find . -type d -name "tmp" -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)✓ Clean complete$(RESET)"

# ==============================================================================
# Help Target
# ==============================================================================

.PHONY: help
## help: Display this help message
help:
	@echo "$(BOLD)$(BLUE)go-xkms Makefile$(RESET)"
	@echo "$(CYAN)Secure key management library with native and shared object support$(RESET)"
	@echo ""
	@echo "$(BOLD)Current Version: $(VERSION)$(RESET)"
	@echo ""
	@echo "$(BOLD)Usage:$(RESET)"
	@echo "  make $(YELLOW)<target>$(RESET)"
	@echo ""
	@echo "$(BOLD)Available Targets:$(RESET)"
	@grep -E '^## [a-zA-Z_-]+:' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-25s$(RESET) %s\n", $$1, $$2}' | \
		sed 's/^## //'
	@echo ""
	@echo "$(BOLD)Backend Build Variables:$(RESET)"
	@echo "  Control which cryptographic backends are included in the build:"
	@echo "  $(GREEN)WITH_PKCS8=1/0$(RESET)       PKCS#8 software keys (default: $(WITH_PKCS8))"
	@echo "  $(GREEN)WITH_TPM2=1/0$(RESET)        TPM 2.0 hardware keys (default: $(WITH_TPM2))"
	@echo "  $(GREEN)WITH_AWS_KMS=1/0$(RESET)     AWS KMS cloud keys (default: $(WITH_AWS_KMS))"
	@echo "  $(GREEN)WITH_GCP_KMS=1/0$(RESET)     GCP KMS cloud keys (default: $(WITH_GCP_KMS))"
	@echo "  $(GREEN)WITH_AZURE_KV=1/0$(RESET)    Azure Key Vault keys (default: $(WITH_AZURE_KV))"
	@echo "  $(GREEN)WITH_PKCS11=1/0$(RESET)      PKCS#11 HSM keys (default: $(WITH_PKCS11))"
	@echo ""
	@echo "$(BOLD)Group Variables (enable all backends for a provider):$(RESET)"
	@echo "  $(GREEN)WITH_AWS=1/0$(RESET)         Enable all AWS backends (default: $(WITH_AWS))"
	@echo "  $(GREEN)WITH_GCP=1/0$(RESET)         Enable all GCP backends (default: $(WITH_GCP))"
	@echo "  $(GREEN)WITH_AZURE=1/0$(RESET)       Enable all Azure backends (default: $(WITH_AZURE))"
	@echo ""
	@echo "  $(CYAN)Examples:$(RESET)"
	@echo "    make build                                    # Default: minimal build"
	@echo "    make build WITH_AWS=1                         # Enable all AWS backends"
	@echo "    make build WITH_AWS_KMS=1 WITH_GCP_KMS=1      # Enable AWS and GCP KMS"
	@echo "    make build WITH_PKCS11=1 WITH_TPM2=1          # Enable hardware backends"
	@echo "    make test WITH_AWS=0 WITH_GCP=0 WITH_AZURE=0  # Test without cloud backends"
	@echo ""
	@echo "  $(YELLOW)Active backend tags:$(RESET) $(BUILD_TAGS)"
	@echo ""
	@echo "$(BOLD)Build Targets:$(RESET)"
	@echo "  $(GREEN)Library:$(RESET)             make lib"
	@echo ""
	@echo "$(BOLD)Common Workflows:$(RESET)"
	@echo "  $(GREEN)Development:$(RESET)         make clean && make all"
	@echo "  $(GREEN)Quick Test:$(RESET)          make test"
	@echo "  $(GREEN)Full CI Check:$(RESET)       make ci"
	@echo "  $(GREEN)Pre-commit:$(RESET)          make verify"
	@echo "  $(GREEN)Integration Tests:$(RESET)   make integration-test"
	@echo "  $(GREEN)Code Quality:$(RESET)        make check"
	@echo "  $(GREEN)Docker Dev:$(RESET)          make docker-run"
	@echo ""
	@echo "$(BOLD)Version Management:$(RESET)"
	@echo "  $(GREEN)Show Version:$(RESET)        make version"
	@echo "  $(GREEN)Bump Major:$(RESET)          make bump-major"
	@echo "  $(GREEN)Bump Minor:$(RESET)          make bump-minor"
	@echo "  $(GREEN)Bump Patch:$(RESET)          make bump-patch"
	@echo "  $(GREEN)Remove Pre-release:$(RESET)  make release-version"
	@echo "  $(GREEN)GitHub Release:$(RESET)      make release"
	@echo ""
	@echo "$(BOLD)Project Info:$(RESET)"
	@echo "  Module:          $(MODULE)"
	@echo "  Go Version:      $$(go version 2>/dev/null | awk '{print $$3}' || echo 'Not installed')"
	@echo "  Coverage Goal:   ≥90%"
	@echo ""

# ==============================================================================
# Protocol Buffer Generation
# ==============================================================================

.PHONY: proto
## proto: Generate Go code from protocol buffer definitions
proto:
	@echo "$(CYAN)$(BOLD)→ Generating Protocol Buffer code...$(RESET)"
	@if [ ! -f "pkg/api/grpc/proto/xkmsv1/xkms.proto" ]; then \
		echo "$(RED)✗ Proto file not found: pkg/api/grpc/proto/xkmsv1/xkms.proto$(RESET)"; \
		exit 1; \
	fi
	@protoc -I/usr/include -I. --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		pkg/api/grpc/proto/xkmsv1/xkms.proto
	@echo "$(GREEN)✓ Protocol Buffer code generated$(RESET)"

.PHONY: proto-check
## proto-check: Verify generated proto code is up to date
proto-check:
	@echo "$(CYAN)$(BOLD)→ Checking Protocol Buffer code...$(RESET)"
	@if [ ! -f "pkg/api/grpc/proto/xkmsv1/xkms.pb.go" ]; then \
		echo "$(RED)✗ Generated proto code not found. Run 'make proto'$(RESET)"; \
		exit 1; \
	fi
	@echo "$(GREEN)✓ Protocol Buffer code exists$(RESET)"

# ==============================================================================
# API Integration Test Targets (test/integration/api)
# ==============================================================================

.PHONY: integration-test-api
## integration-test-api: Run API integration tests for all interfaces
integration-test-api:
	@echo "$(CYAN)$(BOLD)→ Running API integration tests...$(RESET)"
	@test -d $(API_TEST_DIR) || (echo "$(RED)ERROR: API test directory not found: $(API_TEST_DIR)$(RESET)" && exit 1)
	@echo "$(CYAN)  Cleaning up any existing containers...$(RESET)"
	$(call kill_integration_containers)
	@$(API_COMPOSE) down -v --remove-orphans 2>/dev/null || true
	@$(API_COMPOSE) up --build --abort-on-container-exit --exit-code-from integration-tests ; \
		EXIT_CODE=$$? ; \
		$(API_COMPOSE) down -v --remove-orphans ; \
		exit $$EXIT_CODE
	@echo "$(GREEN)$(BOLD)✓ API integration tests complete!$(RESET)"

.PHONY: integration-test-api-up
## integration-test-api-up: Start API test environment
integration-test-api-up:
	@echo "$(CYAN)$(BOLD)→ Starting API test environment...$(RESET)"
	@test -d $(API_TEST_DIR) || (echo "$(RED)ERROR: API test directory not found: $(API_TEST_DIR)$(RESET)" && exit 1)
	@echo "$(CYAN)  Cleaning up any existing containers...$(RESET)"
	$(call kill_integration_containers)
	@$(API_COMPOSE) down -v --remove-orphans 2>/dev/null || true
	@$(API_COMPOSE) up -d xkms-server swtpm softhsm
	@echo "$(GREEN)✓ API test environment started$(RESET)"
	@echo "$(CYAN)REST API: http://localhost:8443$(RESET)"
	@echo "$(CYAN)gRPC:     localhost:9443$(RESET)"
	@echo "$(CYAN)MCP:      localhost:9444$(RESET)"

.PHONY: integration-test-api-down
## integration-test-api-down: Stop API test environment
integration-test-api-down:
	@echo "$(CYAN)→ Stopping API test environment...$(RESET)"
	@test -d $(API_TEST_DIR) || (echo "$(RED)ERROR: API test directory not found: $(API_TEST_DIR)$(RESET)" && exit 1)
	@$(API_COMPOSE) down -v
	@echo "$(GREEN)✓ API test environment stopped$(RESET)"

.PHONY: integration-test-api-logs
## integration-test-api-logs: View API test logs
integration-test-api-logs:
	@test -d $(API_TEST_DIR) || (echo "$(RED)ERROR: API test directory not found: $(API_TEST_DIR)$(RESET)" && exit 1)
	@$(API_COMPOSE) logs -f

.PHONY: integration-test-local-api
## integration-test-local-api: Run API tests locally (requires server running)
integration-test-local-api:
	@echo "$(CYAN)$(BOLD)→ Running API tests locally...$(RESET)"
	@$(GO) test -v -tags='integration frost' ./test/integration/api/... -timeout 10m
	@echo "$(GREEN)$(BOLD)✓ API tests complete!$(RESET)"

# ==============================================================================
# Protocol-Specific API Integration Tests
# All tests run in the devcontainer image and auto-cleanup on completion
# ==============================================================================

# Docker configuration for protocol integration tests
DEVCONTAINER_IMAGE := go-xkms-devcontainer:latest
API_TEST_NETWORK := xkms-api-test
API_COMPOSE := cd $(API_TEST_DIR) && docker compose

# Force kill and remove all xkms integration containers
define kill_integration_containers
	@echo "$(CYAN)  Cleaning up any existing containers...$(RESET)"
	@docker kill xkms-integration-server xkms-integration-swtpm xkms-integration-softhsm xkms-integration-tests 2>/dev/null || true
	@docker rm -f xkms-integration-server xkms-integration-swtpm xkms-integration-softhsm xkms-integration-tests 2>/dev/null || true
	@docker kill xkms-test-unix xkms-test-rest xkms-test-grpc xkms-test-quic xkms-test-mcp xkms-test-frost xkms-test-parity 2>/dev/null || true
	@docker rm -f xkms-test-unix xkms-test-rest xkms-test-grpc xkms-test-quic xkms-test-mcp xkms-test-frost xkms-test-parity 2>/dev/null || true
	@if [ -d $(API_TEST_DIR) ]; then $(API_COMPOSE) down -v --remove-orphans 2>/dev/null || true; fi
endef

.PHONY: integration-test-api-kill
## integration-test-api-kill: Force kill all integration test containers
integration-test-api-kill:
	@echo "$(CYAN)$(BOLD)→ Killing all integration test containers...$(RESET)"
	$(call kill_integration_containers)
	@echo "$(GREEN)✓ All integration test containers killed$(RESET)"

.PHONY: integration-test-api-all
## integration-test-api-all: Run ALL API protocol integration tests (Unix, REST, gRPC, QUIC)
## MCP is excluded: SDK transport speaks HTTP but MCP server speaks JSON-RPC over TCP.
integration-test-api-all: integration-test-api-kill integration-test-api-unix integration-test-api-rest integration-test-api-grpc integration-test-api-quic
	@echo "$(GREEN)$(BOLD)✓ All API protocol integration tests complete!$(RESET)"

.PHONY: integration-test-api-unix
## integration-test-api-unix: Run Unix socket protocol integration tests
integration-test-api-unix:
	@echo "$(CYAN)$(BOLD)→ Running Unix socket protocol integration tests...$(RESET)"
	$(call kill_integration_containers)
	@$(API_COMPOSE) build
	@$(API_COMPOSE) run --rm --name xkms-test-unix integration-tests \
		sh -c "mkdir -p /app/build/bin && CGO_ENABLED=0 go build -buildvcs=false -tags=frost -o /app/build/bin/xkmsctl ./cmd/xkmsctl && go test -v -tags='integration frost codec_cbor codec_json codec_msgpack' ./test/integration/api/unix/... -timeout 10m" ; \
		EXIT_CODE=$$? ; \
		$(API_COMPOSE) down -v --remove-orphans ; \
		exit $$EXIT_CODE
	@echo "$(GREEN)✓ Unix socket protocol integration tests complete$(RESET)"

.PHONY: integration-test-api-rest
## integration-test-api-rest: Run REST API protocol integration tests
integration-test-api-rest:
	@echo "$(CYAN)$(BOLD)→ Running REST API protocol integration tests...$(RESET)"
	$(call kill_integration_containers)
	@$(API_COMPOSE) build
	@$(API_COMPOSE) run --rm --name xkms-test-rest integration-tests \
		sh -c "mkdir -p /app/build/bin && CGO_ENABLED=0 go build -buildvcs=false -tags=frost -o /app/build/bin/xkmsctl ./cmd/xkmsctl && go test -v -tags='integration frost codec_cbor codec_json codec_msgpack' ./test/integration/api/rest/... -timeout 10m" ; \
		EXIT_CODE=$$? ; \
		$(API_COMPOSE) down -v --remove-orphans ; \
		exit $$EXIT_CODE
	@echo "$(GREEN)✓ REST API protocol integration tests complete$(RESET)"

.PHONY: integration-test-api-grpc
## integration-test-api-grpc: Run gRPC protocol integration tests
integration-test-api-grpc:
	@echo "$(CYAN)$(BOLD)→ Running gRPC protocol integration tests...$(RESET)"
	$(call kill_integration_containers)
	@$(API_COMPOSE) build
	@$(API_COMPOSE) run --rm --name xkms-test-grpc integration-tests \
		sh -c "mkdir -p /app/build/bin && CGO_ENABLED=0 go build -buildvcs=false -tags=frost -o /app/build/bin/xkmsctl ./cmd/xkmsctl && go test -v -tags='integration frost codec_cbor codec_json codec_msgpack' ./test/integration/api/grpc/... -timeout 10m" ; \
		EXIT_CODE=$$? ; \
		$(API_COMPOSE) down -v --remove-orphans ; \
		exit $$EXIT_CODE
	@echo "$(GREEN)✓ gRPC protocol integration tests complete$(RESET)"

.PHONY: integration-test-api-quic
## integration-test-api-quic: Run QUIC/HTTP3 protocol integration tests
integration-test-api-quic:
	@echo "$(CYAN)$(BOLD)→ Running QUIC/HTTP3 protocol integration tests...$(RESET)"
	$(call kill_integration_containers)
	@$(API_COMPOSE) build
	@$(API_COMPOSE) run --rm --name xkms-test-quic integration-tests \
		sh -c "mkdir -p /app/build/bin && CGO_ENABLED=0 go build -buildvcs=false -tags=frost -o /app/build/bin/xkmsctl ./cmd/xkmsctl && go test -v -tags='integration frost codec_cbor codec_json codec_msgpack' ./test/integration/api/quic/... -timeout 10m" ; \
		EXIT_CODE=$$? ; \
		$(API_COMPOSE) down -v --remove-orphans ; \
		exit $$EXIT_CODE
	@echo "$(GREEN)✓ QUIC/HTTP3 protocol integration tests complete$(RESET)"

.PHONY: integration-test-api-mcp
## integration-test-api-mcp: Run MCP (Model Context Protocol) integration tests
integration-test-api-mcp:
	@echo "$(CYAN)$(BOLD)→ Running MCP protocol integration tests...$(RESET)"
	$(call kill_integration_containers)
	@$(API_COMPOSE) build
	@$(API_COMPOSE) run --rm --name xkms-test-mcp integration-tests \
		sh -c "mkdir -p /app/build/bin && CGO_ENABLED=0 go build -buildvcs=false -tags=frost -o /app/build/bin/xkmsctl ./cmd/xkmsctl && go test -v -tags='integration frost codec_cbor codec_json codec_msgpack' ./test/integration/api/... -run 'MCP|Mcp' -timeout 10m" ; \
		EXIT_CODE=$$? ; \
		$(API_COMPOSE) down -v --remove-orphans ; \
		exit $$EXIT_CODE
	@echo "$(GREEN)✓ MCP protocol integration tests complete$(RESET)"

.PHONY: integration-test-api-frost
## integration-test-api-frost: Run FROST API integration tests across all protocols
integration-test-api-frost:
ifeq ($(WITH_FROST),1)
	@echo "$(CYAN)$(BOLD)→ Running FROST API integration tests...$(RESET)"
	$(call kill_integration_containers)
	@$(API_COMPOSE) build
	@$(API_COMPOSE) run --rm --name xkms-test-frost integration-tests \
		sh -c "mkdir -p /app/build/bin && CGO_ENABLED=0 go build -buildvcs=false -tags=frost -o /app/build/bin/xkmsctl ./cmd/xkmsctl && go test -v -tags='integration frost codec_cbor codec_json codec_msgpack' ./test/integration/api/... -run 'FROST' -timeout 15m" ; \
		EXIT_CODE=$$? ; \
		$(API_COMPOSE) down -v --remove-orphans ; \
		exit $$EXIT_CODE
	@echo "$(GREEN)✓ FROST API integration tests complete$(RESET)"
else
	@echo "$(YELLOW)⚠ Skipping FROST API tests (WITH_FROST=0)$(RESET)"
	@echo "$(YELLOW)  To enable, run: make integration-test-api-frost WITH_FROST=1$(RESET)"
endif

.PHONY: integration-test-api-parity
## integration-test-api-parity: Run protocol parity tests (verifies all protocols have consistent behavior)
integration-test-api-parity:
	@echo "$(CYAN)$(BOLD)→ Running API protocol parity tests...$(RESET)"
	$(call kill_integration_containers)
	@$(API_COMPOSE) build
	@$(API_COMPOSE) run --rm --name xkms-test-parity integration-tests \
		sh -c "mkdir -p /app/build/bin && CGO_ENABLED=0 go build -buildvcs=false -tags=frost -o /app/build/bin/xkmsctl ./cmd/xkmsctl && go test -v -tags='integration frost codec_cbor codec_json codec_msgpack' ./test/integration/api/... -run 'Parity|AllProtocols' -timeout 20m" ; \
		EXIT_CODE=$$? ; \
		$(API_COMPOSE) down -v --remove-orphans ; \
		exit $$EXIT_CODE
	@echo "$(GREEN)✓ API protocol parity tests complete$(RESET)"

.PHONY: integration-test-sdk-go
## integration-test-sdk-go: Run Go SDK embedded integration tests in devcontainer
integration-test-sdk-go:
	@echo "$(CYAN)$(BOLD)→ Running Go SDK embedded integration tests...$(RESET)"
	$(call run_in_devcontainer,$(GO) test -v -tags='integration codec_cbor codec_json codec_msgpack' ./test/integration/sdk/go/... -run 'TestSDKMultiProtocol$$|TestMultiProtocolKeyOperationsConcurrent|TestMultiProtocolDataIntegrity' -timeout 15m,integration-test-sdk-go)
	@echo "$(GREEN)✓ Go SDK embedded integration tests complete$(RESET)"

.PHONY: integration-test-sdk-go-remote
## integration-test-sdk-go-remote: Run Go SDK remote protocol integration tests against docker-compose server
integration-test-sdk-go-remote:
	@echo "$(CYAN)$(BOLD)→ Running Go SDK remote integration tests...$(RESET)"
	$(call kill_integration_containers)
	@$(API_COMPOSE) build
	@$(API_COMPOSE) run --rm --name xkms-test-sdk-go integration-tests \
		sh -c "go test -v -tags='integration codec_cbor codec_json codec_msgpack' ./test/integration/sdk/go/... -run 'TestSDKMultiProtocolRemote' -timeout 20m" ; \
		EXIT_CODE=$$? ; \
		$(API_COMPOSE) down -v --remove-orphans ; \
		exit $$EXIT_CODE
	@echo "$(GREEN)✓ Go SDK remote integration tests complete$(RESET)"

# ==============================================================================
# Bootstrap Integration Tests
# ==============================================================================

BOOTSTRAP_COMPOSE := docker compose -f test/integration/bootstrap/docker-compose.yml

.PHONY: integration-test-bootstrap
## integration-test-bootstrap: Run bootstrap integration tests (DANE/TLSA, Noise, SPKI, Direct, Auto)
integration-test-bootstrap:
	@echo "$(CYAN)$(BOLD)→ Running bootstrap integration tests...$(RESET)"
	@cd test/integration/bootstrap && docker compose down -v >/dev/null 2>&1 || true
	@cd test/integration/bootstrap && (docker compose run --build --rm test; EXIT_CODE=$$?; docker compose down -v; exit $$EXIT_CODE)
	@echo "$(GREEN)✓ Bootstrap integration tests complete$(RESET)"

.PHONY: show-backends
## show-backends: Display enabled backends for current build configuration
show-backends:
	@echo "$(CYAN)$(BOLD)Current Backend Configuration:$(RESET)"
	@echo ""
	@echo "  $(BOLD)Software Backends:$(RESET)"
	@if [ "$(WITH_PKCS8)" = "1" ]; then echo "    ✓ PKCS8 (Software key storage)"; else echo "    ✗ PKCS8"; fi
	@echo ""
	@echo "  $(BOLD)Hardware Backends:$(RESET)"
	@if [ "$(WITH_PKCS11)" = "1" ]; then echo "    ✓ PKCS11 (HSM)"; else echo "    ✗ PKCS11"; fi
	@if [ "$(WITH_TPM2)" = "1" ]; then echo "    ✓ TPM2 (Trusted Platform Module)"; else echo "    ✗ TPM2"; fi
	@echo ""
	@echo "  $(BOLD)Cloud Backends:$(RESET)"
	@if [ "$(WITH_AWS_KMS)" = "1" ]; then echo "    ✓ AWS KMS"; else echo "    ✗ AWS KMS"; fi
	@if [ "$(WITH_GCP_KMS)" = "1" ]; then echo "    ✓ GCP KMS"; else echo "    ✗ GCP KMS"; fi
	@if [ "$(WITH_AZURE_KV)" = "1" ]; then echo "    ✓ Azure Key Vault"; else echo "    ✗ Azure Key Vault"; fi
	@echo ""
	@echo "  $(BOLD)Build Tags:$(RESET) $(BUILD_TAGS)"

# Include emulator targets
-include Makefile.emulator

# ==============================================================================
# Benchmark Targets
# ==============================================================================

BENCH_DIR := $(BUILD_DIR)/benchmarks
BENCH_OUTPUT := $(BENCH_DIR)/benchmarks-$(shell date +%Y%m%d-%H%M%S).txt
BENCH_BASELINE := $(BENCH_DIR)/benchmarks-baseline.txt

.PHONY: bench
## bench: Run all benchmarks and save results
bench: bench-storage bench-backend bench-xkms bench-api
	@echo "$(GREEN)$(BOLD)✓ All benchmarks complete!$(RESET)"
	@echo "$(CYAN)Results saved to: $(BENCH_OUTPUT)$(RESET)"

.PHONY: bench-storage
## bench-storage: Benchmark storage layer (file, memory)
bench-storage:
	@echo "$(CYAN)$(BOLD)→ Running storage benchmarks...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=. -benchmem -run=^$$ ./pkg/storage/file/... | tee -a $(BENCH_OUTPUT)
	@$(GO) test -bench=. -benchmem -run=^$$ ./pkg/storage/memory/... | tee -a $(BENCH_OUTPUT)
	@echo "$(GREEN)✓ Storage benchmarks complete$(RESET)"

.PHONY: bench-backend
## bench-backend: Benchmark backend operations (AES, software, etc.)
bench-backend:
	@echo "$(CYAN)$(BOLD)→ Running backend benchmarks...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=. -benchmem -run=^$$ ./pkg/keyprovider/symmetric/... | tee -a $(BENCH_OUTPUT)
	@$(GO) test -bench=. -benchmem -run=^$$ ./pkg/backend/software/... | tee -a $(BENCH_OUTPUT)
	@echo "$(GREEN)✓ Backend benchmarks complete$(RESET)"

.PHONY: bench-xkms
## bench-xkms: Benchmark xkms operations (key generation, signing)
bench-xkms:
	@echo "$(CYAN)$(BOLD)→ Running xkms benchmarks...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=. -benchmem -run=^$$ ./pkg/xkms/... | tee -a $(BENCH_OUTPUT)
	@echo "$(GREEN)✓ Xkms benchmarks complete$(RESET)"

.PHONY: bench-api
## bench-api: Benchmark API handlers (REST, gRPC)
bench-api:
	@echo "$(CYAN)$(BOLD)→ Running API benchmarks...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=. -benchmem -run=^$$ ./pkg/api/rest/... | tee -a $(BENCH_OUTPUT)
	@$(GO) test -bench=. -benchmem -run=^$$ ./pkg/api/grpc/... | tee -a $(BENCH_OUTPUT)
	@echo "$(GREEN)✓ API benchmarks complete$(RESET)"

.PHONY: bench-file
## bench-file: Benchmark file storage operations
bench-file:
	@echo "$(CYAN)$(BOLD)→ Running file storage benchmarks...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=. -benchmem -benchtime=5s -run=^$$ ./pkg/storage/file/... | tee $(BENCH_OUTPUT)

.PHONY: bench-aes
## bench-aes: Benchmark AES encryption operations
bench-aes:
	@echo "$(CYAN)$(BOLD)→ Running AES benchmarks...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=. -benchmem -benchtime=5s -run=^$$ ./pkg/keyprovider/symmetric/... | tee $(BENCH_OUTPUT)

.PHONY: bench-software
## bench-software: Benchmark software backend operations
bench-software:
	@echo "$(CYAN)$(BOLD)→ Running software backend benchmarks...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=. -benchmem -benchtime=5s -run=^$$ ./pkg/backend/software/... | tee $(BENCH_OUTPUT)

.PHONY: bench-wrapping
## bench-wrapping: Benchmark key wrapping operations (RSA-OAEP, RSA+AES-KWP, AES-KWP)
bench-wrapping:
	@echo "$(CYAN)$(BOLD)→ Running key wrapping benchmarks...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=. -benchmem -benchtime=3s -run=^$$ ./pkg/crypto/wrapping/... | tee -a $(BENCH_OUTPUT)

.PHONY: bench-jwk
## bench-jwk: Benchmark JWK encoding/decoding and thumbprint operations
bench-jwk:
	@echo "$(CYAN)$(BOLD)→ Running JWK benchmarks...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=. -benchmem -benchtime=3s -run=^$$ ./pkg/encoding/jwk/... | tee -a $(BENCH_OUTPUT)

.PHONY: bench-jwt
## bench-jwt: Benchmark JWT signing and verification operations
bench-jwt:
	@echo "$(CYAN)$(BOLD)→ Running JWT benchmarks...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=. -benchmem -benchtime=3s -run=^$$ ./pkg/encoding/jwt/... | tee -a $(BENCH_OUTPUT)

.PHONY: bench-rest
## bench-rest: Benchmark REST API handlers
bench-rest:
	@echo "$(CYAN)$(BOLD)→ Running REST API benchmarks...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=. -benchmem -benchtime=3s -run=^$$ ./pkg/api/rest/... | tee $(BENCH_OUTPUT)

.PHONY: bench-grpc
## bench-grpc: Benchmark gRPC service operations
bench-grpc:
	@echo "$(CYAN)$(BOLD)→ Running gRPC benchmarks...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=. -benchmem -benchtime=3s -run=^$$ ./pkg/api/grpc/... | tee $(BENCH_OUTPUT)

.PHONY: bench-baseline
## bench-baseline: Create baseline benchmark results
bench-baseline:
	@echo "$(CYAN)$(BOLD)→ Creating benchmark baseline...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@rm -f $(BENCH_BASELINE)
	@$(GO) test -bench=. -benchmem -run=^$$ ./pkg/... | tee $(BENCH_BASELINE)
	@echo "$(GREEN)✓ Baseline saved to: $(BENCH_BASELINE)$(RESET)"

.PHONY: bench-compare
## bench-compare: Compare current benchmarks with baseline (requires benchstat)
bench-compare:
	@echo "$(CYAN)$(BOLD)→ Comparing benchmarks with baseline...$(RESET)"
	@if [ ! -f "$(BENCH_BASELINE)" ]; then \
		echo "$(RED)✗ Baseline not found. Run 'make bench-baseline' first.$(RESET)"; \
		exit 1; \
	fi
	@if ! command -v benchstat >/dev/null 2>&1; then \
		echo "$(YELLOW)⚠ benchstat not found. Installing...$(RESET)"; \
		$(GO) install golang.org/x/perf/cmd/benchstat@latest; \
	fi
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=. -benchmem -run=^$$ ./pkg/... > $(BENCH_DIR)/current.txt
	@benchstat $(BENCH_BASELINE) $(BENCH_DIR)/current.txt
	@echo "$(GREEN)✓ Benchmark comparison complete$(RESET)"

.PHONY: bench-cpu
## bench-cpu: Run benchmarks with CPU profiling
bench-cpu:
	@echo "$(CYAN)$(BOLD)→ Running benchmarks with CPU profiling...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=. -benchmem -cpuprofile=$(BENCH_DIR)/cpu.prof -run=^$$ ./pkg/keyprovider/symmetric/...
	@echo "$(GREEN)✓ CPU profile saved to: $(BENCH_DIR)/cpu.prof$(RESET)"
	@echo "$(CYAN)View with: go tool pprof $(BENCH_DIR)/cpu.prof$(RESET)"

.PHONY: bench-mem
## bench-mem: Run benchmarks with memory profiling
bench-mem:
	@echo "$(CYAN)$(BOLD)→ Running benchmarks with memory profiling...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=. -benchmem -memprofile=$(BENCH_DIR)/mem.prof -run=^$$ ./pkg/keyprovider/symmetric/...
	@echo "$(GREEN)✓ Memory profile saved to: $(BENCH_DIR)/mem.prof$(RESET)"
	@echo "$(CYAN)View with: go tool pprof $(BENCH_DIR)/mem.prof$(RESET)"

# ==============================================================================
# Hardware Certificate Storage Benchmark Targets
# ==============================================================================

.PHONY: bench-pkcs11-certs
## bench-pkcs11-certs: Benchmark PKCS11 certificate storage operations
bench-pkcs11-certs:
	@echo "$(CYAN)$(BOLD)→ Running PKCS11 certificate storage benchmarks...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=BenchmarkPKCS11 -benchmem -benchtime=3s -run=^$$ -tags=pkcs11 \
		./pkg/storage/hardware/... | tee $(BENCH_DIR)/pkcs11-certs.txt
	@echo "$(GREEN)✓ PKCS11 certificate benchmarks complete$(RESET)"
	@echo "$(CYAN)Results saved to: $(BENCH_DIR)/pkcs11-certs.txt$(RESET)"

.PHONY: bench-tpm2-certs
## bench-tpm2-certs: Benchmark TPM2 certificate storage operations
bench-tpm2-certs:
	@echo "$(CYAN)$(BOLD)→ Running TPM2 certificate storage benchmarks...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=BenchmarkTPM2 -benchmem -benchtime=3s -run=^$$ -tags= \
		./pkg/storage/hardware/... | tee $(BENCH_DIR)/tpm2-certs.txt
	@echo "$(GREEN)✓ TPM2 certificate benchmarks complete$(RESET)"
	@echo "$(CYAN)Results saved to: $(BENCH_DIR)/tpm2-certs.txt$(RESET)"

.PHONY: bench-hybrid-certs
## bench-hybrid-certs: Benchmark hybrid certificate storage operations
bench-hybrid-certs:
	@echo "$(CYAN)$(BOLD)→ Running hybrid certificate storage benchmarks...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=BenchmarkHybrid -benchmem -benchtime=3s -run=^$$ -tags="pkcs11" \
		./pkg/storage/hardware/... | tee $(BENCH_DIR)/hybrid-certs.txt
	@echo "$(GREEN)✓ Hybrid certificate benchmarks complete$(RESET)"
	@echo "$(CYAN)Results saved to: $(BENCH_DIR)/hybrid-certs.txt$(RESET)"

.PHONY: bench-cert-comparison
## bench-cert-comparison: Benchmark certificate storage comparison across backends
bench-cert-comparison:
	@echo "$(CYAN)$(BOLD)→ Running certificate storage comparison benchmarks...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=BenchmarkComparison -benchmem -benchtime=3s -run=^$$ -tags="pkcs11" \
		./pkg/storage/hardware/... | tee $(BENCH_DIR)/cert-comparison.txt
	@echo "$(GREEN)✓ Certificate storage comparison benchmarks complete$(RESET)"
	@echo "$(CYAN)Results saved to: $(BENCH_DIR)/cert-comparison.txt$(RESET)"

.PHONY: bench-certs
## bench-certs: Run all certificate storage benchmarks
bench-certs: bench-pkcs11-certs bench-tpm2-certs bench-hybrid-certs bench-cert-comparison
	@echo "$(GREEN)$(BOLD)✓ All certificate storage benchmarks complete!$(RESET)"
	@echo ""
	@echo "$(CYAN)$(BOLD)Benchmark Results Summary:$(RESET)"
	@echo "  PKCS11:     $(BENCH_DIR)/pkcs11-certs.txt"
	@echo "  TPM2:       $(BENCH_DIR)/tpm2-certs.txt"
	@echo "  Hybrid:     $(BENCH_DIR)/hybrid-certs.txt"
	@echo "  Comparison: $(BENCH_DIR)/cert-comparison.txt"
	@echo ""
	@echo "$(CYAN)To compare with baseline, run: make bench-cert-baseline && make bench-cert-compare$(RESET)"

.PHONY: bench-cert-baseline
## bench-cert-baseline: Create baseline for certificate storage benchmarks
bench-cert-baseline:
	@echo "$(CYAN)$(BOLD)→ Creating certificate storage benchmark baseline...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@rm -f $(BENCH_DIR)/cert-baseline.txt
	@$(GO) test -bench=. -benchmem -run=^$$ -tags="pkcs11" \
		./pkg/storage/hardware/... | tee $(BENCH_DIR)/cert-baseline.txt
	@echo "$(GREEN)✓ Baseline saved to: $(BENCH_DIR)/cert-baseline.txt$(RESET)"

.PHONY: bench-cert-compare
## bench-cert-compare: Compare current cert benchmarks with baseline
bench-cert-compare:
	@echo "$(CYAN)$(BOLD)→ Comparing certificate storage benchmarks with baseline...$(RESET)"
	@if [ ! -f "$(BENCH_DIR)/cert-baseline.txt" ]; then \
		echo "$(RED)✗ Baseline not found. Run 'make bench-cert-baseline' first.$(RESET)"; \
		exit 1; \
	fi
	@if ! command -v benchstat >/dev/null 2>&1; then \
		echo "$(YELLOW)⚠ benchstat not found. Installing...$(RESET)"; \
		$(GO) install golang.org/x/perf/cmd/benchstat@latest; \
	fi
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=. -benchmem -run=^$$ -tags="pkcs11" \
		./pkg/storage/hardware/... > $(BENCH_DIR)/cert-current.txt
	@benchstat $(BENCH_DIR)/cert-baseline.txt $(BENCH_DIR)/cert-current.txt | tee $(BENCH_DIR)/cert-comparison-stats.txt
	@echo "$(GREEN)✓ Benchmark comparison complete$(RESET)"
	@echo "$(CYAN)Comparison saved to: $(BENCH_DIR)/cert-comparison-stats.txt$(RESET)"


# ==============================================================================
# Dynamic Test Targets
# ==============================================================================

# Get all packages dynamically (excluding cmd and test dirs)
PKG_DIRS := $(shell go list ./pkg/... 2>/dev/null | sed 's|github.com/jeremyhahn/go-xkms/pkg/||')

# Explicit xkey E2E targets that would otherwise be caught by test-% pattern.
.PHONY: test-e2e-piv-integration
test-e2e-piv-integration:
	@$(MAKE) -C xkey test-e2e-piv-integration

.PHONY: test-e2e-piv-pkcs11
test-e2e-piv-pkcs11:
	@$(MAKE) -C xkey test-e2e-piv-pkcs11

.PHONY: test-fido2-pkcs11
test-fido2-pkcs11:
	@$(MAKE) -C xkey test-fido2-pkcs11

.PHONY: test-fido2-adapter
test-fido2-adapter:
	@$(MAKE) -C xkey test-fido2-adapter

.PHONY: test-pkcs11-all
test-pkcs11-all:
	@$(MAKE) -C xkey test-pkcs11-all

.PHONY: test-e2e
test-e2e:
	@$(MAKE) -C xkey test-e2e

.PHONY: test-e2e-docker
test-e2e-docker:
	@$(MAKE) -C xkey test-e2e-docker

# Dynamic test target for individual packages
# Usage: make test-backend, make test-xkms, etc.
.PHONY: test-%
test-%:
	@echo "[36m→ Running tests for pkg/$*...[0m"
	@$(GO) test -v $(TAG_FLAGS) ./pkg/$*/...
	@echo "[32m✓ Tests passed for pkg/$*[0m"

# Gadget integration tests live in xkey/ module — delegate to xkey Makefile.
.PHONY: integration-test-gadget
integration-test-gadget:
	@$(MAKE) -C xkey integration-test-gadget

# Dynamic integration test target for individual packages
# Usage: make integration-test-backend, make integration-test-pkcs11, etc.
.PHONY: integration-test-%
integration-test-%:
	@echo "[36m→ Running integration tests for $*...[0m"
	@$(GO) test -v -tags=integration $(TAG_FLAGS) ./test/integration/$*/...
	@echo "[32m✓ Integration tests passed for $*[0m"

# Dynamic coverage target for individual packages
# Usage: make coverage-backend, make coverage-xkms, etc.
.PHONY: coverage-%
coverage-%:
	@echo "[36m→ Generating coverage for pkg/$*...[0m"
	@mkdir -p $(COVERAGE_DIR)
	@$(GO) test $(TAG_FLAGS) ./pkg/$*/... -coverprofile=$(COVERAGE_DIR)/$*.out -covermode=atomic
	@$(GO) tool cover -html=$(COVERAGE_DIR)/$*.out -o $(COVERAGE_DIR)/$*-coverage.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/$*.out > $(COVERAGE_DIR)/$*.txt
	@TOTAL=$$(grep '^total:' $(COVERAGE_DIR)/$*.txt | awk '{print $$NF}'); \
	echo "[36m$* coverage: $${TOTAL}[0m"
	@echo "[32m✓ Coverage report: $(COVERAGE_DIR)/$*-coverage.html[0m"


