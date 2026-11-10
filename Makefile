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

# Every pinned tool version and download checksum: GO_IMAGE, GOLANGCI_VERSION,
# ACTIONLINT_VERSION, TRIVY_VERSION and the rest. One file, also sourced by the
# devcontainer image (build/docker/devcontainer/Dockerfile). GO_IMAGE is
# exported for compose, whose devcontainer build requires it.
TOOL_PINS := scripts/tool-pins.sh
include $(TOOL_PINS)
export GO_IMAGE

# GO_BUILD_TAGS: the extra tag set ci-template passes to every stage (#1603).
include scripts/go-build-tags.mk

# Optional features (handbook conventions/build-tags.md). Every feature is
# compiled in by default; opt out with WITH_X=0 to drop it, and its SDKs, from
# the build. A binary built without a feature fails closed when a
# configuration names it (xkms.FeatureNotCompiledError).
WITH_PKCS8 ?= 1
WITH_TPM2 ?= 1
WITH_AWS_KMS ?= 1
WITH_GCP_KMS ?= 1
WITH_AZURE_KV ?= 1
WITH_VAULT ?= 1
WITH_PKCS11 ?= 1

# Object-storage (go-objstore) backends used by the embedded qrdb datastore for
# object-store KV and backup/restore targets. The tag names match go-objstore
# exactly (awss3/minio/gcpstorage/azureblob/glacier/azurearchive).
WITH_AWS_S3 ?= 1
WITH_MINIO ?= 1
WITH_GCP_STORAGE ?= 1
WITH_AZURE_BLOB ?= 1
WITH_GLACIER ?= 1
WITH_AZURE_ARCHIVE ?= 1

# Quantum-safe cryptography (ML-DSA, ML-KEM) is always enabled.
# Uses pure-Go implementations (circl, crypto/mlkem). No external libraries required.

# FROST threshold signatures (RFC 9591)
WITH_FROST ?= 1

# Every per-feature toggle, in one list: build-full sets each to 1 and
# build-minimal each to 0.
FEATURE_TOGGLES := WITH_PKCS8 WITH_TPM2 WITH_AWS_KMS WITH_GCP_KMS WITH_AZURE_KV \
	WITH_VAULT WITH_PKCS11 WITH_FROST WITH_AWS_S3 WITH_MINIO WITH_GCP_STORAGE \
	WITH_AZURE_BLOB WITH_GLACIER WITH_AZURE_ARCHIVE

# Provider umbrellas: unset by default. WITH_AWS=0 (or 1) sets the provider's
# KMS backend and object-storage family together, overriding the individual
# toggles; left unset, the individual toggles decide.
WITH_AWS ?=
WITH_GCP ?=
WITH_AZURE ?=
ifneq ($(WITH_AWS),)
	WITH_AWS_KMS := $(WITH_AWS)
	WITH_AWS_S3 := $(WITH_AWS)
	WITH_GLACIER := $(WITH_AWS)
endif
ifneq ($(WITH_GCP),)
	WITH_GCP_KMS := $(WITH_GCP)
	WITH_GCP_STORAGE := $(WITH_GCP)
endif
ifneq ($(WITH_AZURE),)
	WITH_AZURE_KV := $(WITH_AZURE)
	WITH_AZURE_BLOB := $(WITH_AZURE)
	WITH_AZURE_ARCHIVE := $(WITH_AZURE)
endif


# All available build tags for release builds
# CLI doesn't include pkcs11 (requires CGO) for easier distribution
CLI_BUILD_TAGS := pkcs8 awskms gcpkms azurekv vault frost codec_cbor codec_json codec_msgpack gms_pure_go
# Server includes all tags including pkcs11 and the object-storage cloud backends
SERVER_BUILD_TAGS := pkcs8 awskms gcpkms azurekv vault pkcs11 frost awss3 minio gcpstorage azureblob glacier azurearchive codec_cbor codec_json codec_msgpack
# All tags for integration testing (includes all possible build tags)
ALL_TAGS := integration frost pkcs8 pkcs11 awskms gcpkms azurekv vault nitrokey fido2 webauthn awss3 minio gcpstorage azureblob glacier azurearchive codec_cbor codec_json codec_msgpack

# Build tags based on backend flags (for development/testing)
# Codec tags are always required for go-qrdb DAO layer serialization
BUILD_TAGS := codec_cbor codec_json codec_msgpack
ifeq ($(WITH_PKCS8),1)
	BUILD_TAGS += pkcs8
endif
ifeq ($(WITH_TPM2),1)
	BUILD_TAGS += tpm2
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
# Object-storage (go-objstore) cloud backends.
ifeq ($(WITH_AWS_S3),1)
	BUILD_TAGS += awss3
endif
ifeq ($(WITH_MINIO),1)
	BUILD_TAGS += minio
endif
ifeq ($(WITH_GCP_STORAGE),1)
	BUILD_TAGS += gcpstorage
endif
ifeq ($(WITH_AZURE_BLOB),1)
	BUILD_TAGS += azureblob
endif
ifeq ($(WITH_GLACIER),1)
	BUILD_TAGS += glacier
endif
ifeq ($(WITH_AZURE_ARCHIVE),1)
	BUILD_TAGS += azurearchive
endif


# Build tag flags for go commands
ifneq ($(call go_tags,$(BUILD_TAGS)),)
	TAG_FLAGS := -tags "$(call go_tags,$(BUILD_TAGS))"
else
	TAG_FLAGS :=
endif

# xkey's production tag set comes from xkey/Makefile, the one place it is
# declared. Every resolved toggle (umbrellas already applied) is passed on the
# sub-make's command line: a $(shell) child does not inherit this make's
# command-line variables on GNU make before 4.4, nor makefile assignments on
# any version. Deferred (=) so only the recipes that build xkey pay for the
# sub-make.
XKEY_BUILD_TAGS = $(shell $(MAKE) -s --no-print-directory -C xkey \
	$(foreach toggle,$(FEATURE_TOGGLES),$(toggle)=$($(toggle))) print-build-tags)

# The pure-Go xkmsctl carries every selected feature except pkcs11, which
# needs cgo.
CLI_TAGS := $(filter-out pkcs11,$(BUILD_TAGS)) gms_pure_go

# Go parameters
#
# The module declares the Go it needs in go.mod's `go` directive, and the
# fleet pins GOTOOLCHAIN=local on hosts, under which a host go older than that
# directive refuses every target ("go: go.mod requires go >= 1.27.3 (running
# go 1.26.4; GOTOOLCHAIN=local)") while the Docker builder, which runs with
# GOTOOLCHAIN=auto, quietly downloads the right one. Select the declared
# toolchain explicitly for every recipe: the host go then acts only as the
# bootstrapper and fetches that exact version once, so `make build` gives the
# same toolchain on every host and in CI, and a host upgrade is not a
# prerequisite for building. Exported, so it reaches golangci-lint and every
# nested go invocation too. Override with `make GOTOOLCHAIN=local ...` if a
# host deliberately wants its own go.
GO_MOD_VERSION := $(shell awk '/^go [0-9]/{print $$2; exit}' go.mod)
export GOTOOLCHAIN ?= go$(GO_MOD_VERSION)
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
#
# Tagged with $(IMAGE_TAG), not a literal `latest`, for the same reason the
# compose files are: an image tag is daemon-global. `builder-image` and
# `docker-build` each build a tag and then immediately run or consume it, so
# a second job retagging in that window makes the first build or test against
# the wrong image. IMAGE_TAG is `latest` off CI, so local names do not change.
#
# Recursive (=), not simple (:=): IMAGE_TAG is defined further down with the
# rest of the namespacing, and := would expand it here as empty.
DOCKER_IMAGE = $(PROJECT_NAME):$(IMAGE_TAG)
DOCKER_INTEGRATION_IMAGE = $(PROJECT_NAME)-integration:$(IMAGE_TAG)
DOCKER_CONTAINER := $(PROJECT_NAME)-container
BUILDER_IMAGE = $(PROJECT_NAME)-builder:$(IMAGE_TAG)
XKEY_BUILDER_IMAGE = $(PROJECT_NAME)-xkey-builder:$(IMAGE_TAG)

# Inside the toolchain image (build/docker/devcontainer/Dockerfile sets
# XKMS_NATIVE_BUILD=1) every native dependency is present and no Docker daemon
# is, so the CGO builds run in place and `build` takes the local xkey build.
# Everywhere else they run in the builder images, as before.
ifeq ($(XKMS_NATIVE_BUILD),1)
CGO_BUILDER_DEP :=
CGO_RUN := bash -c
BUILD_XKEY_TARGET := build-xkey-local
else
CGO_BUILDER_DEP := builder-image
CGO_RUN = docker run --rm -v $(CURDIR):/workspace:cached $(BUILDER_MODULE_ENV) -w /workspace $(BUILDER_IMAGE) bash -c
BUILD_XKEY_TARGET := build-xkey
endif

# Cross-repo first-party modules resolve from Gitea tags inside containers
# (dependency-resolution.md §6) — no workspace, no sibling mounts. The
# read-only fetch token comes from the gitignored build/docker/devcontainer/.env
# (pattern: go-qrdb/.devcontainer/); for the root builder containers the host
# module cache is mounted (BUILDER_MODULE_ENV) so a warm host cache serves
# container builds without refetching the graph. GOMODCACHE is pinned to the
# mount path inside those containers: the golang base image keeps its cache
# at /go/pkg/mod, so without the pin the mount sat unused, every container
# build refetched the graph, and a checkout with no build/docker/devcontainer/.env failed
# on the first private module ("Failed to authenticate user") even with a
# fully warm host cache.
FORGE_MODULE_TOKEN ?= $(shell sed -n 's/^FORGE_MODULE_TOKEN=//p' build/docker/devcontainer/.env 2>/dev/null)
# Exported so docker compose invocations interpolate ${FORGE_MODULE_TOKEN} in
# their environment blocks regardless of which directory compose runs from.
export FORGE_MODULE_TOKEN
# The Gitea server itself (host:port of its HTTP API) is never written into
# this tree: scripts/gitea-host.sh derives it from the environment, from
# build/docker/devcontainer/.env, or from this checkout's own origin remote (an SSH origin
# maps its port to the HTTP port), and prints nothing for a GitHub origin --
# the public resolution path, in which no insteadOf rewrite is emitted at
# all. `make gitea-host` shows the resolved value. Exported for the same
# reason as the token: every compose file interpolates ${GITEA_HOST}.
GITEA_HOST ?= $(shell scripts/gitea-host.sh 2>/dev/null)
export GITEA_HOST
# The insteadOf rewrite that resolves github.com/jeremyhahn/* against Gitea.
GITEA_INSTEADOF_KEY = url.http://x:$(FORGE_MODULE_TOKEN)@$(GITEA_HOST)/jeremyhahn/.insteadOf

# The module-fetch credentials every container gets, resolved ONCE here for
# all consumers: the gomodauth BuildKit secret (stage-gomodauth), the builder
# containers (GITEA_MODULE_ENV) and every compose file's environment block.
# Two sources, checked in order:
#   1. GIT_CONFIG_KEY_0 already in the environment -- this is how Gitea Actions
#      supplies them (runner.envs injects the composed insteadOf rewrite into
#      every job's process env; dependency-resolution.md §6). There is no
#      FORGE_MODULE_TOKEN on that runner and no build/docker/devcontainer/.env in its checkout,
#      so this must be checked first or the job gets an empty-token rewrite
#      ("Failed to authenticate user"). Only entry 0 is forwarded (the
#      rewrite), so the count is always 1: git aborts with "missing config
#      key GIT_CONFIG_KEY_1" when the caller's count of N > 1 crosses over
#      without entries 1..N-1, which fails every module fetch.
#   2. FORGE_MODULE_TOKEN and GITEA_HOST, composed into GITEA_INSTEADOF_KEY -- the
#      devcontainer/host path, sourced from the gitignored build/docker/devcontainer/.env.
# Otherwise the count is 0: git reads exactly GIT_CONFIG_COUNT entries, so
# KEY_0/VALUE_0 stay inert and every module resolves publicly.
#
# The compose files read `${GOMODAUTH_GIT_CONFIG_COUNT:-${GITEA_HOST:+1}}` and
# likewise for KEY_0/VALUE_0, falling back to the token rewrite when make is
# not in the picture -- build/docker/devcontainer/devcontainer.json loads the compose file
# DIRECTLY, so a devcontainer whose build/docker/devcontainer/.env supplies the token and
# host must still get the rewrite. These exports are the override for the
# make path, not the only source.
#
# A required `${GITEA_HOST:?...}` cannot serve here: compose evaluates it when
# the file is LOADED, so it fails a public checkout before any service starts,
# which is the opposite of the public-resolution path this exists to provide.
ifneq ($(GIT_CONFIG_KEY_0),)
GOMODAUTH_GOPRIVATE := $(if $(GOPRIVATE),$(GOPRIVATE),github.com/jeremyhahn/*)
GOMODAUTH_GIT_CONFIG_COUNT := 1
GOMODAUTH_GIT_CONFIG_KEY_0 := $(GIT_CONFIG_KEY_0)
GOMODAUTH_GIT_CONFIG_VALUE_0 := $(GIT_CONFIG_VALUE_0)
else ifneq ($(and $(FORGE_MODULE_TOKEN),$(GITEA_HOST)),)
GOMODAUTH_GOPRIVATE := github.com/jeremyhahn/*
GOMODAUTH_GIT_CONFIG_COUNT := 1
GOMODAUTH_GIT_CONFIG_KEY_0 := $(GITEA_INSTEADOF_KEY)
GOMODAUTH_GIT_CONFIG_VALUE_0 := https://github.com/jeremyhahn/
else
GOMODAUTH_GIT_CONFIG_COUNT := 0
endif
export GOMODAUTH_GOPRIVATE GOMODAUTH_GIT_CONFIG_COUNT GOMODAUTH_GIT_CONFIG_KEY_0 GOMODAUTH_GIT_CONFIG_VALUE_0

# ==============================================================================
# Compose project namespacing
# ==============================================================================
#
# A docker compose project name is HOST-GLOBAL: it is the prefix for every
# container, network and volume the stack creates. Every stack in this repo
# used to take that name from a constant -- `go-xkms` for the devcontainer,
# the directory basename (`storage`, `tpm2`, ...) for the per-lane suites --
# so two CI jobs on the same runner host competed for the identical set of
# names and the loser died before a single test ran:
#
#   Container xkms-dev-swtpm  Error response from daemon: Conflict. The
#   container name "/xkms-dev-swtpm" is already in use by container "70d3..."
#
# A crashed or cancelled job made it permanent: its stack was never torn down,
# so the orphans blocked every later run on that host until someone cleared
# them by hand.
#
# COMPOSE_NS namespaces the project per job. GITHUB_RUN_ID is unique per CI
# run and is set by Gitea Actions as well as GitHub Actions; it falls back to
# `local` off CI so a developer's stack (and its build/module caches) stays
# stable across invocations instead of leaking a new project every time.
#
# $(call compose,<lane>) is the ONLY way this Makefile may invoke compose. The
# lane suffix reproduces the per-suite isolation the directory basename used
# to provide -- concurrent lanes must not share a project, or `down` in one
# tears the network out from under another.
#
# Namespacing the project is necessary but not sufficient: an explicit
# `container_name:`, `networks: name:` or a fixed host port binding in a
# compose file is absolute and overrides the project prefix entirely. The
# harness compose files therefore declare none of those -- see
# build/docker/devcontainer/compose.yaml.
#
# IT_PROJECT is the compose project ci-template v1.25's integration and soak
# jobs pass, go-xkms-ci-<run>-<attempt>[-soak-<i>]; COMPOSE_RUN_ID is then that
# name without the go-xkms- prefix, so COMPOSE_NS is IT_PROJECT exactly.
COMPOSE_RUN_ID ?= $(if $(IT_PROJECT),$(patsubst go-xkms-%,%,$(IT_PROJECT)),$(shell echo "$${GITHUB_RUN_ID:-local}"))
COMPOSE_NS := go-xkms-$(COMPOSE_RUN_ID)

# Both -p and COMPOSE_PROJECT_NAME, deliberately:
#   -p                    outranks a compose file's top-level `name:` in every
#                         compose version -- build/docker/devcontainer/compose.yaml
#                         pins `name: go-xkms`, and the flag is the only way to
#                         be certain the per-run namespace wins over it.
#   COMPOSE_PROJECT_NAME  is inherited by child processes, so a script a recipe
#                         shells out to lands in the same project instead of
#                         silently falling back to its directory basename.
compose = COMPOSE_PROJECT_NAME=$(COMPOSE_NS)-$(1) docker compose -p $(COMPOSE_NS)-$(1)

# An image TAG is daemon-global -- the project namespace does not reach it.
# `docker build -t go-xkms-integration:latest` on one job retags that name for
# every job on the host, so two runs building different commits race between
# `compose build` and `compose run`: the loser's container is created from the
# other run's image and silently tests the wrong commit. Tagging per run
# removes the shared name.
#
# The tag carries the repository name, not the bare run id. A run id is unique
# within a repository, not on a Docker host: two repositories building on the
# same runner can both be at run 143, and the fixture images this repo builds
# from a sibling working tree (go-quicbaas-server) carry a name that sibling
# builds too. `go-xkms-<run id>` is unambiguous on the host, which is what
# makes tag-matched cleanup below safe.
#
# Empty off CI, where each compose file's own default applies
# (`${XKMS_IMAGE_TAG:-latest}`, `:-dev`, `:-sdk-test`) -- so a developer's
# image names and layer cache are exactly what they were.
ifneq ($(COMPOSE_RUN_ID),local)
XKMS_IMAGE_TAG ?= $(COMPOSE_NS)
endif
export XKMS_IMAGE_TAG

# The image repositories this harness builds, as `docker images --filter
# reference=` patterns. clean-run-images removes a reference only when its
# repository is on this list: a tag is something any build on the host may
# carry, so it is not on its own proof of ownership.
XKMS_IMAGE_REPOS := 'go-xkms-*' 'go-xkms/*' 'go-quicbaas-server'

# The effective tag for images this Makefile builds directly (as opposed to
# through compose, where each file spells its own default inline).
IMAGE_TAG = $(if $(XKMS_IMAGE_TAG),$(XKMS_IMAGE_TAG),latest)

# The tag the devcontainer stack's xkms-server image carries, mirroring that
# compose file's `${XKMS_IMAGE_TAG:-dev}` so lookups find what compose built.
XKMS_SERVER_IMAGE = go-xkms-server:$(if $(XKMS_IMAGE_TAG),$(XKMS_IMAGE_TAG),dev)
GOMODCACHE_HOST := $(shell go env GOMODCACHE 2>/dev/null || echo $(HOME)/go/pkg/mod)
ifneq ($(GOMODAUTH_GIT_CONFIG_COUNT),0)
GITEA_MODULE_ENV := -e GOWORK=off \
                    -e GOPRIVATE='$(GOMODAUTH_GOPRIVATE)' \
                    -e GIT_CONFIG_COUNT='$(GOMODAUTH_GIT_CONFIG_COUNT)' \
                    -e GIT_CONFIG_KEY_0='$(GOMODAUTH_GIT_CONFIG_KEY_0)' \
                    -e GIT_CONFIG_VALUE_0='$(GOMODAUTH_GIT_CONFIG_VALUE_0)'
else
# No module-fetch credentials: every module resolves publicly.
GITEA_MODULE_ENV := -e GOWORK=off
endif
# The warm host module cache, for containers that run AS ROOT only: the
# builder images (Dockerfile.builder, xkey/Dockerfile.builder, Dockerfile.ci)
# declare no USER. The integration image runs `make test` as testuser
# (Dockerfile), which cannot traverse /root, so docker-run and docker-test take
# GITEA_MODULE_ENV alone and resolve modules inside the image as before.
BUILDER_MODULE_ENV := $(GITEA_MODULE_ENV) \
                    -e GOMODCACHE=/root/go/pkg/mod \
                    -v $(GOMODCACHE_HOST):/root/go/pkg/mod:cached

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
# Path to this repo inside go-xkms's OWN devcontainer (build/docker/devcontainer/, compose
# project $(COMPOSE_NS)-devcontainer, service `devcontainer`), which bind-mounts
# the repo at /workspace. Every in-container path below is derived from this
# variable, so pointing it elsewhere is all that is needed to drive a container
# that mounts go-xkms somewhere other than /workspace.
DEVCONTAINER_REPO ?= /workspace
# TCP (gRPC over TCP)
XKMS_GRPC_ADDR ?= localhost:9443
# Container gRPC address (for tests running inside devcontainer network)
XKMS_GRPC_ADDR_CONTAINER ?= xkms-server:9443
# PKCS#11 module path inside container
PKCS11_MODULE_CONTAINER := $(DEVCONTAINER_REPO)/build/lib/libxkms_pkcs11.so
# FIPS PKCS#11 module path inside container (the GOFIPS140-compiled artifact,
# used by FIPS lanes that dlopen the .so so they exercise the real FIPS build
# rather than a non-FIPS build merely run under the GOFIPS140 environment).
PKCS11_MODULE_FIPS_CONTAINER := $(DEVCONTAINER_REPO)/build/lib/libxkms_pkcs11_fips.so
XKMS_GRPC_TLS_ENABLED ?= false
XKMS_GRPC_TLS_INSECURE ?= true

# FIPS 140-3 build selection for the PKCS#11 module.
#
# GOFIPS140 is the Go toolchain variable that compiles in the FIPS 140-3 crypto
# module. The non-FIPS build defaults it to "off"; the FIPS build defaults it to
# "latest". Both are user-overridable, so an operator can pin an exact certified
# module version at build time, e.g.:
#
#   make build-pkcs11-module-fips GOFIPS140_FIPS=v1.0.0
#
# The FIPS artifact is emitted alongside the non-FIPS one as
# libxkms_pkcs11_fips.so and self-identifies as FIPS in its CK_INFO /
# CK_TOKEN_INFO labels via fips.Built() — the GOFIPS140 value recorded here in
# the binary's build metadata, which no environment variable alters. It is NOT
# crypto/fips140.Enabled(), which is module state: GODEBUG=fips140=off turns
# that false on this very artifact, and the labels used to move with it (#219).
GOFIPS140 ?= off
GOFIPS140_FIPS ?= latest

# Test timeout
PKCS11_TEST_TIMEOUT ?= 10m
# Backends the OpenSSL matrix exercises. Naming a backend asserts it is
# compiled in; the matrix fails rather than skips if it is not.
XKMS_PKCS11_BACKENDS ?= software

# Test configuration - include codec build tags for go-codec support
# Include frost tag for threshold signature scheme unit tests (issue #703)
TEST_TAGS := codec_cbor codec_json codec_msgpack tpm_simulator frost
# Per-binary go test bound for the unit lanes CI's Unit Tests job runs through
# `make coverage` (#1587): above that job's slowest green run, 70m, and below
# its 140m timeout-minutes, so a hung test fails with a goroutine dump first.
UNIT_TEST_TIMEOUT ?= 75m
TEST_FLAGS := -v -race -timeout $(UNIT_TEST_TIMEOUT) -tags="$(call go_tags,$(TEST_TAGS))"
# FIPS variant. The `fips` tag has to join the SAME -tags list rather than
# arrive as a second flag: go test keeps only the last -tags it is given, so
# appending a flag would silently drop the codec tags above.
TEST_FLAGS_FIPS := -v -race -timeout $(UNIT_TEST_TIMEOUT) -tags="$(call go_tags,$(TEST_TAGS) fips)"
# !frost stub variant: TEST_TAGS minus frost, so the *_frost_stub_test.go
# files (pkg/api/rest, pkg/api/mcp, pkg/api/grpc, pkg/server) build and run
# under the "FROST not compiled in" configuration instead of being silently
# excluded by every other test lane, which always carries frost (go-xkms#1249).
TEST_TAGS_NOFROST := $(filter-out frost,$(TEST_TAGS))
TEST_FLAGS_NOFROST := -v -race -timeout $(UNIT_TEST_TIMEOUT) -tags="$(call go_tags,$(TEST_TAGS_NOFROST))"
COVERAGE_FILE := $(COVERAGE_DIR)/coverage.out
# Where `make agsim` puts the trusted-firmware host simulators. Exported so every
# go test the Makefile runs finds them (sdk/go/tfwsim reads TFWSIM_DIR).
TFWSIM_DIR ?= $(CURDIR)/build/agsim
export TFWSIM_DIR
COVERAGE_HTML := $(COVERAGE_DIR)/coverage.html
COVERAGE_THRESHOLD := 80
# Integration test tags include both backend tags and integration tag
ifneq ($(BUILD_TAGS),)
	INTEGRATION_TEST_FLAGS := -v -tags="$(call go_tags,integration pkcs8 pkcs11 codec_cbor codec_json codec_msgpack $(BUILD_TAGS))"
else
	INTEGRATION_TEST_FLAGS := -v -tags="$(call go_tags,integration pkcs8 pkcs11 codec_cbor codec_json codec_msgpack)"
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
	@echo "$(YELLOW)Note: unit tests need SWTPM (pkg/tpm2/vtpm runs real vTPMs); integration tests also need SoftHSM:$(RESET)"
	@echo "  - Ubuntu/Debian: sudo apt-get install swtpm swtpm-tools"
	@echo "  - SoftHSM 2.7.0+: sudo sh scripts/build-softhsm.sh (distro 2.6.1 cannot report PKCS#11 tamper)"
	@echo "  - macOS: brew install softhsm swtpm (SoftHSM 2.7.0+ for PKCS#11 tamper classification)"

.PHONY: build
## build: Build the shared library, CLI, server binaries, and xkey (default)
build: lib build-cli build-servers $(BUILD_XKEY_TARGET)

.PHONY: build-local
## build-local: Build everything locally without Docker (requires dev packages)
build-local: lib build-cli build-xkey-local

.PHONY: build-full
## build-full: Compile every package and build xkmsctl + xkmsd locally with every WITH_* feature on
build-full:
	@$(MAKE) --no-print-directory build-profile BUILD_PROFILE=full $(addsuffix =1,$(FEATURE_TOGGLES))

.PHONY: build-minimal
## build-minimal: Compile every package and build xkmsctl + xkmsd locally with every WITH_* feature off
build-minimal:
	@$(MAKE) --no-print-directory build-profile BUILD_PROFILE=minimal $(addsuffix =0,$(FEATURE_TOGGLES))

# build-profile compiles the module and links xkmsctl and xkmsd under the
# feature toggles its caller sets; build-full and build-minimal drive it.
.PHONY: build-profile
build-profile:
	@echo "$(CYAN)$(BOLD)→ Building the $(BUILD_PROFILE) profile [tags: $(BUILD_TAGS)]$(RESET)"
	@mkdir -p $(BIN_DIR)
	@CGO_ENABLED=1 $(GO) build -buildvcs=false $(TAG_FLAGS) ./...
	@$(MAKE) --no-print-directory build-cli
	@CGO_ENABLED=1 $(GOBUILD) -o $(BIN_DIR)/xkmsd ./cmd/xkmsd
	@echo "$(GREEN)✓ $(BUILD_PROFILE) profile built: $(BIN_DIR)/xkmsctl $(BIN_DIR)/xkmsd$(RESET)"

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
	@CGO_ENABLED=0 $(GO) build -buildvcs=false -tags "$(call go_tags,$(CLI_TAGS))" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/xkmsctl ./cmd/xkmsctl
	@echo "$(GREEN)✓ CLI binary built: $(BIN_DIR)/xkmsctl$(RESET)"

.PHONY: build-cli-gui
## build-cli-gui: Build xkmsctl with `xkmsctl acme gui`, the Wails desktop ACME admin GUI
## Wails needs cgo + WebKit (webkit2gtk-4.1); the admin frontend is embedded from
## pkg/acme/web/packages/admin/dist.
build-cli-gui:
	@echo "$(CYAN)$(BOLD)→ Building xkmsctl CLI with the desktop admin GUI...$(RESET)"
	@mkdir -p $(BIN_DIR)
	@CGO_ENABLED=1 $(GO) build -buildvcs=false -tags "$(call go_tags,$(CLI_TAGS) gui production webkit2_41)" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/xkmsctl ./cmd/xkmsctl
	@echo "$(GREEN)✓ CLI binary built with GUI: $(BIN_DIR)/xkmsctl$(RESET)"

.PHONY: build-server
## build-server: Build the unified xkmsd server binary (uses Docker for CGO deps)
build-server: $(CGO_BUILDER_DEP)
	@echo "$(CYAN)$(BOLD)→ Building unified xkmsd server...$(RESET)"
	@mkdir -p $(BIN_DIR)
	@$(CGO_RUN) "CGO_ENABLED=1 go build -buildvcs=false -tags '$(call go_tags,$(BUILD_TAGS))' -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/xkmsd ./cmd/xkmsd/"
	@echo "$(GREEN)✓ Unified server binary built: $(BIN_DIR)/xkmsd$(RESET)"

.PHONY: build-servers
## build-servers: Build server binary (alias for build-server)
build-servers: build-server
	@echo "$(GREEN)$(BOLD)✓ Server binary built successfully!$(RESET)"

.PHONY: build-xkey
## build-xkey: Build the xkey binary with embedded GUI frontend (uses Docker)
## Modules resolve from Gitea tags via GITEA_MODULE_ENV (dependency-resolution.md §6).
## The binary is output to $(BIN_DIR)/xkey alongside other project binaries.
build-xkey:
	@echo "$(CYAN)$(BOLD)→ Building xkey builder image...$(RESET)"
	@DOCKER_BUILDKIT=0 docker build -t $(XKEY_BUILDER_IMAGE) -f xkey/Dockerfile.builder xkey/ >/dev/null 2>&1
	@echo "$(CYAN)$(BOLD)→ Building xkey frontend...$(RESET)"
	@docker run --rm \
		-v $(CURDIR):/workspace:cached \
		-w /workspace/xkey/frontend \
		$(XKEY_BUILDER_IMAGE) \
		bash -c "npm ci --silent && node ./node_modules/vite/bin/vite.js build && chown -R $(shell id -u):$(shell id -g) dist/ node_modules/"
	@echo "$(CYAN)$(BOLD)→ Building xkey browser extension...$(RESET)"
	@docker run --rm \
		-v $(CURDIR):/workspace:cached \
		-w /workspace/xkey/extension \
		$(XKEY_BUILDER_IMAGE) \
		bash -c "set -e && rm -rf node_modules && npm ci --silent && node node_modules/typescript/lib/tsc.js && cp manifest.json dist/ && cp src/popup.html dist/ && mkdir -p dist/icons && (cp -r src/icons/* dist/icons/ 2>/dev/null || true) && chown -R $(shell id -u):$(shell id -g) dist/ node_modules/"
	@echo "$(CYAN)$(BOLD)→ Building xkey binary...$(RESET)"
	@mkdir -p $(BIN_DIR)
	@docker run --rm \
		-v $(CURDIR):/workspace:cached \
		$(BUILDER_MODULE_ENV) \
		-w /workspace/xkey \
		$(XKEY_BUILDER_IMAGE) \
		bash -c "CGO_ENABLED=1 go build -tags '$(call go_tags,$(XKEY_BUILD_TAGS))' -buildvcs=false -ldflags '-X github.com/jeremyhahn/go-xkms/xkey/cmd/xkey/cmd.Version=$(VERSION) -X github.com/jeremyhahn/go-xkms/xkey/cmd/xkey/cmd.Commit=$(GIT_COMMIT) -X github.com/jeremyhahn/go-xkms/xkey/cmd/xkey/cmd.Date=$(BUILD_DATE)' -o /workspace/$(BIN_DIR)/xkey ./cmd/xkey && chown $(shell id -u):$(shell id -g) /workspace/$(BIN_DIR)/xkey"
	@echo "$(GREEN)✓ xkey binary built: $(BIN_DIR)/xkey$(RESET)"
	@echo "$(GREEN)  GUI mode:  ./$(BIN_DIR)/xkey$(RESET)"
	@echo "$(GREEN)  CLI mode:  ./$(BIN_DIR)/xkey --no-gui$(RESET)"

.PHONY: build-xkey-local
## build-xkey-local: Build xkey locally without Docker (requires dev packages)
## xkey/Makefile writes directly to this project's $(BIN_DIR) — no copy.
build-xkey-local:
	@$(MAKE) -C xkey build-local
	@echo "$(GREEN)✓ xkey binary built at: $(BIN_DIR)/xkey$(RESET)"

# ==============================================================================
# Web UI Targets (server console SPA + TypeScript SDK)
# ==============================================================================
#
# The SPA (web/app) consumes two workspace packages through npm `file:` deps:
#   @go-xkms/sdk         → sdk/ts        (built: needs dist/)
#   @go-xkms/svelte-auth → sdk/ts/svelte-auth (source-only)
# The built dist/ is copied to two embed roots: web/dist (daemon `ui` build
# tag) and web/desktop/frontend/dist (the future Wails shell). npm targets
# no-op with a warning when npm is unavailable so a Go-only checkout still
# builds.

WEB_APP_DIR := web/app
SDK_TS_DIR := sdk/ts
SVELTE_AUTH_DIR := sdk/ts/svelte-auth
XKEY_FRONTEND_DIR := xkey/frontend
NPM := $(shell command -v npm 2>/dev/null)

.PHONY: build-sdk-ts
## build-sdk-ts: Build and test the @go-xkms/sdk TypeScript client
build-sdk-ts:
ifeq ($(NPM),)
	@echo "$(YELLOW)⚠ npm not found; skipping build-sdk-ts$(RESET)"
else
	@echo "$(CYAN)$(BOLD)→ Building @go-xkms/sdk...$(RESET)"
	@cd $(SDK_TS_DIR) && npm ci --silent && npm run build && npm test
	@echo "$(GREEN)✓ @go-xkms/sdk built$(RESET)"
endif

.PHONY: build-web
## build-web: Build the server console SPA and stage it for embedding
build-web: build-sdk-ts
ifeq ($(NPM),)
	@echo "$(YELLOW)⚠ npm not found; skipping build-web$(RESET)"
else
	@echo "$(CYAN)$(BOLD)→ Installing web/app dependencies...$(RESET)"
	@cd $(WEB_APP_DIR) && npm ci --silent
	@# npm rewrites file: deps to relative symlinks; force absolute symlinks so
	@# resolution survives regardless of the working directory, then assert the
	@# entrypoints resolve before building.
	@mkdir -p $(WEB_APP_DIR)/node_modules/@go-xkms
	@rm -rf $(WEB_APP_DIR)/node_modules/@go-xkms/sdk $(WEB_APP_DIR)/node_modules/@go-xkms/svelte-auth
	@ln -sfn $(CURDIR)/$(SDK_TS_DIR) $(WEB_APP_DIR)/node_modules/@go-xkms/sdk
	@ln -sfn $(CURDIR)/$(SVELTE_AUTH_DIR) $(WEB_APP_DIR)/node_modules/@go-xkms/svelte-auth
	@test -f $(CURDIR)/$(SDK_TS_DIR)/dist/index.js || { echo "$(RED)✗ @go-xkms/sdk dist missing; run build-sdk-ts$(RESET)"; exit 1; }
	@test -f $(CURDIR)/$(SVELTE_AUTH_DIR)/src/index.ts || { echo "$(RED)✗ @go-xkms/svelte-auth src missing$(RESET)"; exit 1; }
	@echo "$(CYAN)$(BOLD)→ Building web/app SPA...$(RESET)"
	@cd $(WEB_APP_DIR) && npm run build
	@test -f $(WEB_APP_DIR)/dist/index.html || { echo "$(RED)✗ web/app build produced no dist/index.html$(RESET)"; exit 1; }
	@echo "$(CYAN)$(BOLD)→ Staging dist for daemon and desktop embeds...$(RESET)"
	@rm -rf web/dist && mkdir -p web/dist && cp -r $(WEB_APP_DIR)/dist/. web/dist/
	@mkdir -p web/desktop/frontend/dist && rm -rf web/desktop/frontend/dist && mkdir -p web/desktop/frontend/dist && cp -r $(WEB_APP_DIR)/dist/. web/desktop/frontend/dist/
	@echo "$(GREEN)✓ web UI built and staged (web/dist, web/desktop/frontend/dist)$(RESET)"
endif

.PHONY: build-ui
## build-ui: Build xkmsd with the embedded web UI (requires build-web first)
build-ui: build-web
	@echo "$(CYAN)$(BOLD)→ Building xkmsd with embedded web UI...$(RESET)"
	@mkdir -p $(BIN_DIR)
	@$(GO) build -tags "$(call go_tags,ui $(SERVER_BUILD_TAGS))" -o $(BIN_DIR)/xkmsd ./cmd/xkmsd
	@echo "$(GREEN)✓ xkmsd (with web UI) built: $(BIN_DIR)/xkmsd$(RESET)"

.PHONY: dev-web
## dev-web: Run the SPA dev server (proxies to XKMS_DEV_API, default :8443)
dev-web:
ifeq ($(NPM),)
	@echo "$(YELLOW)⚠ npm not found; cannot run dev-web$(RESET)"
else
	@cd $(WEB_APP_DIR) && XKMS_DEV_API=$${XKMS_DEV_API:-https://localhost:8443} npm run dev
endif

.PHONY: build-desktop
## build-desktop: Build the Wails desktop console (embeds the SPA)
## The GUI needs cgo + WebKit; build under the "desktop" tag. Depends on
## build-web to stage the SPA into web/desktop/frontend/dist first.
build-desktop: build-web
	@echo "$(CYAN)$(BOLD)→ Building xKMS desktop console...$(RESET)"
	@mkdir -p $(BIN_DIR)
	@cd web/desktop && CGO_ENABLED=1 $(GO) build -tags "$(call go_tags,desktop production webkit2_41)" \
		-o $(CURDIR)/$(BIN_DIR)/xkms-console . && \
		echo "$(GREEN)✓ xKMS desktop console built: $(BIN_DIR)/xkms-console$(RESET)"

.PHONY: test-web
## test-web: Type-check and unit-test the SDK, svelte-auth, and SPA
## Runs under coverage so the 90% thresholds in each vitest config gate the
## build — a plain `vitest run` reports no coverage and enforces nothing.
test-web:
ifeq ($(NPM),)
	@echo "$(YELLOW)⚠ npm not found; skipping test-web$(RESET)"
else
	@echo "$(CYAN)$(BOLD)→ Testing @go-xkms/sdk...$(RESET)"
	@cd $(SDK_TS_DIR) && npm ci --silent && npm run test:coverage
	@echo "$(CYAN)$(BOLD)→ Testing @go-xkms/svelte-auth...$(RESET)"
	@cd $(SVELTE_AUTH_DIR) && npm ci --silent && npm run test:coverage
	@echo "$(CYAN)$(BOLD)→ Type-checking and testing web/app...$(RESET)"
	@cd $(WEB_APP_DIR) && npm ci --silent && npm run check && npm run test:coverage
	@echo "$(CYAN)$(BOLD)→ Type-checking and testing the xKey GUI frontend...$(RESET)"
	@cd $(XKEY_FRONTEND_DIR) && npm ci --silent && npm run check -- --fail-on-warnings && npm test
	@echo "$(GREEN)✓ web UI tests passed$(RESET)"
endif

# The xKey GUI's Wails bindings are generated from its Go services. The wails
# CLI is run at the version xkey/go.mod pins, as pkg@version so its own
# dependencies stay out of xkey's module, with the build tags wails.json names.
XKEY_WAILS_VERSION = $(shell awk '/github.com\/wailsapp\/wails\/v2 /{print $$2}' xkey/go.mod)
XKEY_WAILS_TAGS = $(shell sed -n 's/.*"tags": *"\([^"]*\)".*/\1/p' xkey/wails.json)

.PHONY: generate-wailsjs
## generate-wailsjs: Regenerate the xKey GUI's Wails bindings (xkey/frontend/wailsjs)
generate-wailsjs:
	@echo "$(CYAN)$(BOLD)→ Generating the xKey GUI's Wails bindings ($(XKEY_WAILS_VERSION))...$(RESET)"
	@cd xkey && out=$$(GOWORK=off $(GO) run github.com/wailsapp/wails/v2/cmd/wails@$(XKEY_WAILS_VERSION) generate module -tags "$(XKEY_WAILS_TAGS)" 2>&1) || { echo "$$out"; exit 1; }

.PHONY: check-wailsjs
## check-wailsjs: Fail when the committed Wails bindings differ from the Go services
check-wailsjs: generate-wailsjs
	@if [ -n "$$(git -c core.fileMode=false status --porcelain --untracked-files=all -- $(XKEY_FRONTEND_DIR)/wailsjs)" ]; then \
		echo "$(RED)$(BOLD)✗ The xKey GUI's Wails bindings are out of date with its Go services:$(RESET)"; \
		git -c core.fileMode=false status --short -- $(XKEY_FRONTEND_DIR)/wailsjs; \
		echo "$(YELLOW)  Commit the regenerated $(XKEY_FRONTEND_DIR)/wailsjs (make generate-wailsjs).$(RESET)"; \
		exit 1; \
	fi
	@echo "$(GREEN)✓ Wails bindings match the Go services$(RESET)"

.PHONY: test-web-e2e
## test-web-e2e: Playwright mock-API tier (hermetic; no server required)
## Drives the real SPA against page.route() interception, so it needs only a
## browser — the live-server tier is integration-test-web.
test-web-e2e:
ifeq ($(NPM),)
	@echo "$(YELLOW)⚠ npm not found; skipping test-web-e2e$(RESET)"
else
	@echo "$(CYAN)$(BOLD)→ Running web console e2e (mock API tier)...$(RESET)"
	@cd $(WEB_APP_DIR) && npm ci --silent && npx playwright install --with-deps chromium && npm run e2e
	@echo "$(GREEN)✓ web e2e (mock tier) passed$(RESET)"
endif

.PHONY: integration-test-web
## integration-test-web: Playwright live-server tier against a real xkmsd
## Boots a real daemon (run-server.sh) and drives passkey login through
## Chrome's CDP virtual WebAuthn authenticator.
integration-test-web:
ifeq ($(NPM),)
	@echo "$(YELLOW)⚠ npm not found; skipping integration-test-web$(RESET)"
else
	@echo "$(CYAN)$(BOLD)→ Running web console e2e (live server tier)...$(RESET)"
	@cd test/integration/web && npm ci --silent && npx playwright install --with-deps chromium && npx playwright test
	@echo "$(GREEN)✓ web e2e (live tier) passed$(RESET)"
endif

.PHONY: coverage-sdk-ts
## coverage-sdk-ts: Coverage report for @go-xkms/sdk (sdk/ts/coverage/)
coverage-sdk-ts:
ifeq ($(NPM),)
	@echo "$(YELLOW)⚠ npm not found; skipping coverage-sdk-ts$(RESET)"
else
	@echo "$(CYAN)$(BOLD)→ Coverage: @go-xkms/sdk...$(RESET)"
	@cd $(SDK_TS_DIR) && npm ci --silent && npm run test:coverage
endif

.PHONY: coverage-svelte-auth
## coverage-svelte-auth: Coverage report for @go-xkms/svelte-auth
coverage-svelte-auth:
ifeq ($(NPM),)
	@echo "$(YELLOW)⚠ npm not found; skipping coverage-svelte-auth$(RESET)"
else
	@echo "$(CYAN)$(BOLD)→ Coverage: @go-xkms/svelte-auth...$(RESET)"
	@cd $(SVELTE_AUTH_DIR) && npm ci --silent && npm run test:coverage
endif

.PHONY: coverage-web-app
## coverage-web-app: Coverage report for the web/app SPA
coverage-web-app:
ifeq ($(NPM),)
	@echo "$(YELLOW)⚠ npm not found; skipping coverage-web-app$(RESET)"
else
	@echo "$(CYAN)$(BOLD)→ Coverage: web/app SPA...$(RESET)"
	@cd $(WEB_APP_DIR) && npm ci --silent && npm run test:coverage
endif

.PHONY: coverage-web
## coverage-web: Coverage for all three web packages (SDK, svelte-auth, SPA)
coverage-web: coverage-sdk-ts coverage-svelte-auth coverage-web-app
	@echo "$(GREEN)✓ web coverage reports written (lcov + text per package)$(RESET)"

# ==============================================================================
# PKCS#11 Module Targets
# ==============================================================================

.PHONY: build-pkcs11-module
## build-pkcs11-module: Build the PKCS#11 shared library (libxkms_pkcs11.so). GOFIPS140 defaults to off.
build-pkcs11-module:
	@echo "$(CYAN)$(BOLD)→ Building PKCS#11 shared library (GOFIPS140=$(GOFIPS140))...$(RESET)"
	@mkdir -p $(LIB_DIR)
	@GOFIPS140=$(GOFIPS140) CGO_ENABLED=1 $(GO) build $(TAG_FLAGS) -buildmode=c-shared \
		-o $(LIB_DIR)/libxkms_pkcs11.so \
		./cmd/pkcs11-module
	@echo "$(GREEN)✓ PKCS#11 module built: $(LIB_DIR)/libxkms_pkcs11.so$(RESET)"

.PHONY: build-pkcs11-module-fips
## build-pkcs11-module-fips: Build the FIPS 140-3 PKCS#11 shared library (libxkms_pkcs11_fips.so). GOFIPS140_FIPS defaults to latest; pin with GOFIPS140_FIPS=v1.0.0.
build-pkcs11-module-fips:
	@echo "$(CYAN)$(BOLD)→ Building FIPS 140-3 PKCS#11 shared library (GOFIPS140=$(GOFIPS140_FIPS))...$(RESET)"
	@mkdir -p $(LIB_DIR)
	@GOFIPS140=$(GOFIPS140_FIPS) CGO_ENABLED=1 $(GO) build $(TAG_FLAGS) -buildmode=c-shared \
		-o $(LIB_DIR)/libxkms_pkcs11_fips.so \
		./cmd/pkcs11-module
	@echo "$(GREEN)✓ FIPS PKCS#11 module built: $(LIB_DIR)/libxkms_pkcs11_fips.so$(RESET)"

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
	@$(GOTEST) $(TEST_FLAGS) ./pkg/fido2/uhid/...

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
	@$(GOTEST) $(TEST_FLAGS) -run TestWebAuthnVerification ./pkg/fido2/authenticator/...

.PHONY: test-authenticator
## test-authenticator: Run the CTAP2 authenticator package unit tests
test-authenticator:
	@echo "$(CYAN)→ Testing CTAP2 authenticator package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/fido2/authenticator/...

.PHONY: coverage-uhid
## coverage-uhid: Generate UHID package coverage report
coverage-uhid:
	@echo "$(CYAN)→ Generating UHID coverage report...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/uhid.out -covermode=atomic ./pkg/fido2/uhid/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/uhid.out -o $(COVERAGE_DIR)/uhid.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/uhid.out | tail -1
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/uhid.html$(RESET)"

.PHONY: coverage-xkey-cmd
## coverage-xkey-cmd: Generate xkey command coverage report
coverage-xkey-cmd:
	@echo "$(CYAN)→ Generating xkey command coverage report...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@# tpm_simulator, as xkey's own TEST_TAGS: the TPM commands' tests run on
	@# the in-process simulator and are invisible to a run without it.
	@cd xkey && $(GO) test -tags "$(call go_tags,$(BUILD_TAGS) tpm_simulator)" -race -coverprofile=../$(COVERAGE_DIR)/xkey-cmd.out -covermode=atomic ./cmd/xkey/...
	@cd xkey && $(GO) tool cover -html=../$(COVERAGE_DIR)/xkey-cmd.out -o ../$(COVERAGE_DIR)/xkey-cmd.html
	@cd xkey && $(GO) tool cover -func=../$(COVERAGE_DIR)/xkey-cmd.out | tail -1
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
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -buildvcs=false -tags="$(call go_tags,$(CLI_BUILD_TAGS))" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsctl-linux-amd64 ./cmd/xkmsctl
	@echo "$(CYAN)  Building linux/arm64...$(RESET)"
	@GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build -buildvcs=false -tags="$(call go_tags,$(CLI_BUILD_TAGS))" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsctl-linux-arm64 ./cmd/xkmsctl
	@echo "$(CYAN)  Building darwin/amd64...$(RESET)"
	@GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 $(GO) build -buildvcs=false -tags="$(call go_tags,$(CLI_BUILD_TAGS))" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsctl-darwin-amd64 ./cmd/xkmsctl
	@echo "$(CYAN)  Building darwin/arm64...$(RESET)"
	@GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GO) build -buildvcs=false -tags="$(call go_tags,$(CLI_BUILD_TAGS))" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsctl-darwin-arm64 ./cmd/xkmsctl
	@echo "$(CYAN)  Building windows/amd64...$(RESET)"
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -buildvcs=false -tags="$(call go_tags,$(CLI_BUILD_TAGS))" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsctl-windows-amd64.exe ./cmd/xkmsctl
	@echo "$(CYAN)  Building windows/arm64...$(RESET)"
	@GOOS=windows GOARCH=arm64 CGO_ENABLED=0 $(GO) build -buildvcs=false -tags="$(call go_tags,$(CLI_BUILD_TAGS))" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsctl-windows-arm64.exe ./cmd/xkmsctl
	@echo "$(GREEN)✓ xkmsctl binaries built for all platforms$(RESET)"

.PHONY: release-server
## release-server: Build xkmsd for all platforms with ALL build tags (including pkcs11)
release-server:
	@echo "$(CYAN)$(BOLD)→ Building xkmsd for all platforms (with all tags including pkcs11)...$(RESET)"
	@mkdir -p $(BIN_DIR)/release
	@echo "$(CYAN)  Building linux/amd64...$(RESET)"
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=1 $(GO) build -buildvcs=false -tags="$(call go_tags,$(SERVER_BUILD_TAGS))" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsd-linux-amd64 ./cmd/xkmsd/
	@echo "$(CYAN)  Building linux/arm64...$(RESET)"
	@GOOS=linux GOARCH=arm64 CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc $(GO) build -buildvcs=false -tags="$(call go_tags,$(SERVER_BUILD_TAGS))" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsd-linux-arm64 ./cmd/xkmsd/ || echo "$(YELLOW)⚠ Cross-compilation for linux/arm64 requires aarch64-linux-gnu-gcc$(RESET)"
	@echo "$(CYAN)  Building darwin/amd64...$(RESET)"
	@GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 $(GO) build -buildvcs=false -tags="$(call go_tags,$(SERVER_BUILD_TAGS))" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsd-darwin-amd64 ./cmd/xkmsd/ || echo "$(YELLOW)⚠ Cross-compilation for darwin/amd64 may require macOS SDK$(RESET)"
	@echo "$(CYAN)  Building darwin/arm64...$(RESET)"
	@GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 $(GO) build -buildvcs=false -tags="$(call go_tags,$(SERVER_BUILD_TAGS))" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsd-darwin-arm64 ./cmd/xkmsd/ || echo "$(YELLOW)⚠ Cross-compilation for darwin/arm64 may require macOS SDK$(RESET)"
	@echo "$(CYAN)  Building windows/amd64...$(RESET)"
	@GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc $(GO) build -buildvcs=false -tags="$(call go_tags,$(SERVER_BUILD_TAGS))" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsd-windows-amd64.exe ./cmd/xkmsd/ || echo "$(YELLOW)⚠ Cross-compilation for windows/amd64 requires mingw-w64$(RESET)"
	@echo "$(CYAN)  Building windows/arm64...$(RESET)"
	@GOOS=windows GOARCH=arm64 CGO_ENABLED=1 $(GO) build -buildvcs=false -tags="$(call go_tags,$(SERVER_BUILD_TAGS))" -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/release/xkmsd-windows-arm64.exe ./cmd/xkmsd/ || echo "$(YELLOW)⚠ Cross-compilation for windows/arm64 requires appropriate cross-compiler$(RESET)"
	@echo "$(GREEN)✓ xkmsd binaries built for all platforms$(RESET)"

.PHONY: lib
## lib: Build shared library (libxkms-VERSION.so) using Docker for CGO deps
lib: $(CGO_BUILDER_DEP)
	@echo "$(CYAN)$(BOLD)→ Building shared object library (version $(VERSION))...$(RESET)"
	@mkdir -p $(LIB_DIR)
	@$(CGO_RUN) "CGO_ENABLED=1 go build -buildvcs=false -tags '$(call go_tags,$(BUILD_TAGS))' -ldflags '$(LDFLAGS)' -buildmode=c-shared -o $(SHARED_LIB) $(CGO_SOURCE)/main.go"
	@echo "$(GREEN)✓ Shared library built: $(SHARED_LIB)$(RESET)"
	@rm -f $(SHARED_LIB_LINK)
	@cd $(LIB_DIR) && ln -s libxkms-$(VERSION).so libxkms.so
	@echo "$(GREEN)✓ Symlink created: $(SHARED_LIB_LINK) -> libxkms-$(VERSION).so$(RESET)"

.PHONY: test
## test: Run unit tests with coverage (Go + web UI; fast, in-memory)
## Sub-makes rather than prerequisites so the Go suites always report before
## the web suites even under `make -j`; make aborts on the first failure, so a
## red web suite still fails the target.
# Unit tests never reach the host's hardware TPM (pkg/tpm2/tpmdev): a test
# binary is refused by itself, and this flag holds every process a test runs
# (a built binary, a child) to the same rule. Opt in with
# XKMS_TEST_HARDWARE_TPM=1.
test test-go: export XKMS_DENY_HARDWARE_TPM := 1
test:
	@$(MAKE) --no-print-directory test-scripts
	@$(MAKE) --no-print-directory test-go
	@$(MAKE) --no-print-directory test-nofrost
	@$(MAKE) --no-print-directory test-pkcs11
	@$(MAKE) --no-print-directory test-web
	@$(MAKE) --no-print-directory check-wailsjs
	@echo "$(GREEN)$(BOLD)✓ All unit tests passed (shell + Go + web)!$(RESET)"

.PHONY: test-scripts
## test-scripts: Run the shell-level tests for test/scripts helpers
# These need no Docker daemon: they drive the scripts against a fake `docker`
# on PATH. clean-test-containers.sh decides which Docker resources a CI run may
# destroy on a SHARED Actions host, so its scope boundary is gated here
# (go-xkms#2) rather than discovered by another repository's job dying.
test-scripts:
	@echo "$(CYAN)$(BOLD)→ Running shell script tests...$(RESET)"
	@bash test/scripts/clean-test-containers.test.sh
	@bash test/scripts/release-alpha.test.sh
	@bash test/scripts/release-tag.test.sh
	@bash test/scripts/release-assets.test.sh
	@bash test/scripts/changelog-assemble.test.sh
	@bash test/scripts/retry.test.sh
	@bash test/scripts/in-toolchain-image.test.sh
	@bash test/scripts/softhsm-pin.test.sh
	@bash test/scripts/open-server-barrier.test.sh
	@bash test/scripts/ensure-server-ca.test.sh
	@bash test/scripts/socket-probe.test.sh
	@bash test/scripts/start-test-xkmsd.test.sh
	@bash test/scripts/xkms-server-diagnostics.test.sh
	@bash test/scripts/check-public-literals.test.sh
	@bash test/scripts/build-agsim.test.sh
	@bash test/scripts/check-test-helpers.test.sh
	@bash test/scripts/xkey-build-tags.test.sh
	@bash test/scripts/go-build-tags.test.sh
	@bash test/scripts/gomodauth.test.sh
	@bash test/scripts/credential-ignores.test.sh
	@bash test/scripts/no-credential-echo.test.sh
	@bash test/scripts/ci-registry.test.sh
	@bash test/scripts/in-toolchain-image.test.sh
	@echo "$(GREEN)✓ Shell script tests passed$(RESET)"

# test-buildgates: the CI tier gate (#1483) -- every ci.yml job is in CI Gate
# with a pr/full tag that matches its `if:`. Pure file parsing, no build tags.
.PHONY: test-buildgates
test-buildgates:
	@$(GO) test -timeout 45m ./internal/buildgates/...

.PHONY: test-go unit-test-pkgs
## test-go: Run the Go unit tests with coverage
# Package exclusions from this lane (issue #703 -- every other exclusion
# regex used to carry was unjustified and has been removed; pkg/pkcs11/...,
# pkg/crypto/rand, pkg/storage/hardware, pkg/keyprovider/quantum, pkg/quantum,
# cmd/xkmsd and cmd/pkcs11-module all build and run under $(TEST_TAGS) with no
# extra setup, so they run here now):
#   pkg/tpm2$$             - the simulator suite links -lcrypto (go-tpm-tools);
#                            this job's environment doesn't install
#                            libssl-dev, only the dedicated tpm2-simulator job
#                            does. Measured by `make coverage-tpm2-simulator`
#                            and merged into the report by `coverage-packages`.
#   /mocks, /testutil       - generated/hand-written test doubles, not
#   pkcs11test, /proto        production code; excluded from the per-package
#                              threshold report in scripts/check-coverage.sh
#   yubikey, smartcardhsm   - tests that need physical hardware to exercise
UNIT_TEST_SCOPE := ./pkg/... ./cmd/... ./sdk/...
UNIT_TEST_EXCLUDE := (pkg/tpm2$$|/mocks|/testutil|/proto|pkcs11test|yubikey|smartcardhsm)

## unit-test-pkgs: Print test-go's package list (batch.yml's race scope)
unit-test-pkgs:
	@go list -e $(UNIT_TEST_SCOPE) 2>/dev/null | grep -v -E "$(UNIT_TEST_EXCLUDE)"

test-go: check-insecure-tls agsim
	@echo "$(CYAN)$(BOLD)→ Running unit tests...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@bash -c 'set -o pipefail; \
	$(GO) test $(TEST_FLAGS) -coverprofile=$(COVERAGE_FILE) -covermode=atomic \
		$$(go list -e $(UNIT_TEST_SCOPE) 2>/dev/null | grep -v -E "$(UNIT_TEST_EXCLUDE)") \
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

.PHONY: test-pkcs11
## test-pkcs11: Run the pkcs11-tagged password-vault key-factor tests (pkg/vaulttoken)
## on SoftHSM, whose token lives in a temp directory. test-go builds without
## pkcs11 (CGO), so without this lane those tests never run.
test-pkcs11:
	@echo "$(CYAN)$(BOLD)→ Running PKCS#11 vault key-factor tests...$(RESET)"
	@$(GOTEST) -v -race -timeout $(UNIT_TEST_TIMEOUT) -tags="$(call go_tags,$(TEST_TAGS) pkcs11)" ./pkg/vaulttoken/...
	@echo "$(GREEN)✓ PKCS#11 vault key-factor tests passed$(RESET)"

.PHONY: test-nofrost
## test-nofrost: Run the !frost stub-build unit tests (pkg/api/rest, pkg/api/mcp,
## pkg/api/grpc, pkg/server) with the CI tags minus frost. These packages carry
## *_frost_stub_test.go files that only build without the frost tag, exercising
## the "FROST not compiled in" refusal paths; test-go always carries frost, so
## without this lane those files never build in CI (go-xkms#1249).
test-nofrost:
	@echo "$(CYAN)$(BOLD)→ Running !frost stub unit tests...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS_NOFROST) ./pkg/api/rest/... ./pkg/api/mcp/... ./pkg/api/grpc/... ./pkg/server/...
	@echo "$(GREEN)✓ !frost stub unit tests complete$(RESET)"

.PHONY: test-all
## test-all: Run ALL unit tests including hardware backends and import/export
test-all: test test-importexport
	@echo "$(GREEN)$(BOLD)✓ All unit tests (including hardware backends) complete!$(RESET)"

.PHONY: race
## race: Run tests with race detector on all backends (matches GitHub Actions)
race: agsim
	@echo "$(CYAN)$(BOLD)→ Running race detector tests with all backends...$(RESET)"
	@CGO_ENABLED=1 $(GO) test -race -tags="$(call go_tags,pkcs8$(comma)awskms$(comma)gcpkms$(comma)azurekv$(comma)pkcs11$(comma)vault$(comma)codec_cbor$(comma)codec_json$(comma)codec_msgpack)" ./... || \
		(echo "$(RED)$(BOLD)✗ Race detector found issues$(RESET)" && exit 1)
	@echo "$(GREEN)$(BOLD)✓ Race detector tests passed!$(RESET)"

.PHONY: coverage
## coverage: Run the unit suite and fail when total coverage is below COVERAGE_THRESHOLD (CI's test stage)
# GOMEMLIMIT and -p=2 bound the suite's memory: under -race the Argon2-heavy
# REST/MCP packages exhaust a runner's memory without them. Under CI the suite
# must leave the tree as it found it (#454). The per-package report is
# advisory (#704).
coverage: export GOMEMLIMIT := 10GiB
coverage: export GOFLAGS := $(strip $(GOFLAGS) -p=2)
coverage: test
	@$(MAKE) --no-print-directory coverage-gate

# coverage-gate: the threshold, the dirty-tree check (#454) and the advisory
# per-package report (#704) on $(COVERAGE_FILE), shared by coverage and
# coverage-merge.
.PHONY: coverage-gate
coverage-gate:
	@total=$$($(GO) tool cover -func=$(COVERAGE_FILE) | awk '/^total:/ {print $$3}' | tr -d %); \
	echo "Total coverage: $${total}%"; \
	awk -v c="$$total" -v t="$(COVERAGE_THRESHOLD)" 'BEGIN { if (c + 0 < t + 0) { print "coverage below " t "%"; exit 1 } }'
	@if [ -n "$$CI" ] && [ -n "$$(git status --porcelain)" ]; then \
		git status --porcelain; echo "the unit suite left the tree dirty (#454)"; exit 1; \
	fi
	@$(MAKE) --no-print-directory coverage-threshold-report || echo "per-package report is non-blocking (#704)"

# coverage-shard and coverage-merge (DS-8139, CA m2406(2)): make coverage
# never finished on a GitHub-hosted runner, so CI runs the unit suite as
# SHARDS jobs. Shard SHARD tests every SHARDS-th package of test-go's sorted
# list (round robin) with test-go's flags into $(COVERAGE_DIR)/shard-$(SHARD).out;
# shard 1 also runs make test's other parts (shell, !frost, pkcs11, web,
# wailsjs). coverage-merge joins the shard profiles into $(COVERAGE_FILE)
# and runs coverage-gate. GOMEMLIMIT stays below the hosted 8g container.
SHARD ?= 1
SHARDS ?= 1

.PHONY: coverage-shard-pkgs coverage-shard coverage-merge
## coverage-shard-pkgs: Print shard SHARD of SHARDS of test-go's package list
coverage-shard-pkgs:
	@go list -e $(UNIT_TEST_SCOPE) 2>/dev/null | grep -v -E "$(UNIT_TEST_EXCLUDE)" | LC_ALL=C sort | \
		awk -v s="$(SHARD)" -v n="$(SHARDS)" '(NR - 1) % n == s - 1'

## coverage-shard: Run unit test shard SHARD of SHARDS with coverage (CI's test stage)
coverage-shard: export XKMS_DENY_HARDWARE_TPM := 1
coverage-shard: export GOMEMLIMIT := 5GiB
coverage-shard: export GOFLAGS := $(strip $(GOFLAGS) -p=2)
coverage-shard: check-insecure-tls agsim
	@echo "$(CYAN)$(BOLD)→ Running unit test shard $(SHARD)/$(SHARDS)...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@if [ "$(SHARD)" = 1 ]; then $(MAKE) --no-print-directory test-scripts; fi
	@bash -c 'set -o pipefail; \
	pkgs=$$($(MAKE) -s --no-print-directory coverage-shard-pkgs); \
	if [ -z "$$pkgs" ]; then echo "$(RED)✗ shard $(SHARD)/$(SHARDS) has no packages$(RESET)"; exit 1; fi; \
	echo "shard $(SHARD)/$(SHARDS): $$(echo "$$pkgs" | wc -l) packages"; \
	$(GO) test $(TEST_FLAGS) -coverprofile=$(COVERAGE_DIR)/shard-$(SHARD).out -covermode=atomic $$pkgs \
		2>&1 | tee $(COVERAGE_DIR)/shard-$(SHARD).log; \
	EXIT_CODE=$${PIPESTATUS[0]}; \
	if [ $$EXIT_CODE -ne 0 ]; then \
		echo "$(RED)$(BOLD)✗ Unit test shard $(SHARD)/$(SHARDS) failed with exit code $$EXIT_CODE$(RESET)"; \
		grep -E "FAIL|panic" $(COVERAGE_DIR)/shard-$(SHARD).log | head -20; \
		exit $$EXIT_CODE; \
	fi'
	@if [ "$(SHARD)" = 1 ]; then \
		$(MAKE) --no-print-directory test-nofrost && \
		$(MAKE) --no-print-directory test-pkcs11 && \
		$(MAKE) --no-print-directory test-web && \
		$(MAKE) --no-print-directory check-wailsjs; \
	fi
	@if [ -n "$$CI" ] && [ -n "$$(git status --porcelain)" ]; then \
		git status --porcelain; echo "unit test shard $(SHARD)/$(SHARDS) left the tree dirty (#454)"; exit 1; \
	fi
	@echo "$(GREEN)$(BOLD)✓ Unit test shard $(SHARD)/$(SHARDS) passed$(RESET)"

## coverage-merge: Merge the shard profiles into COVERAGE_FILE, then the threshold
coverage-merge:
	@profiles=$$(find $(COVERAGE_DIR) -name 'shard-*.out' | LC_ALL=C sort); \
	if [ -z "$$profiles" ]; then echo "$(RED)✗ no shard profiles in $(COVERAGE_DIR)$(RESET)"; exit 1; fi; \
	modes=$$(head -q -n 1 $$profiles | sort -u); \
	if [ "$$(echo "$$modes" | wc -l)" -ne 1 ] || [ "$${modes#mode: }" = "$$modes" ]; then \
		echo "$(RED)✗ shard profiles disagree on mode: $$modes$(RESET)"; exit 1; \
	fi; \
	{ echo "$$modes"; for f in $$profiles; do tail -n +2 "$$f"; done; } > $(COVERAGE_FILE).tmp; \
	mv $(COVERAGE_FILE).tmp $(COVERAGE_FILE); \
	echo "Merged $$(echo "$$profiles" | wc -l) shard profiles into $(COVERAGE_FILE)"
	@$(MAKE) --no-print-directory coverage-gate

.PHONY: coverage-full
## coverage-full: Generate comprehensive coverage report (unit + integration tests)
coverage-full: agsim
	@echo "$(CYAN)$(BOLD)→ Running comprehensive coverage tests (unit + integration)...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Step 1: Running unit tests with coverage...$(RESET)"
	@$(GO) test $(TEST_FLAGS) -coverprofile=$(COVERAGE_DIR)/unit.out -covermode=atomic \
		$$(go list -e ./pkg/... 2>/dev/null | grep -v -E "$(UNIT_TEST_EXCLUDE)") \
		2>&1 | tee $(COVERAGE_DIR)/unit.log; \
		unit_exit=$$?; \
		if [ ! -f "$(COVERAGE_DIR)/unit.out" ] || [ ! -s "$(COVERAGE_DIR)/unit.out" ]; then \
			echo "$(RED)✗ Unit test coverage profile missing or empty$(RESET)"; \
			exit 1; \
		fi; \
		if [ $$unit_exit -ne 0 ]; then exit $$unit_exit; fi
	@echo "$(CYAN)→ Step 2: Running integration tests with coverage...$(RESET)"
	@$(GOTEST) -v -tags="$(call go_tags,integration codec_cbor codec_json codec_msgpack)" -coverprofile=$(COVERAGE_DIR)/integration.out -covermode=atomic \
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
		2>&1 | tee $(COVERAGE_DIR)/integration.log; \
		integration_exit=$$?; \
		if [ ! -f "$(COVERAGE_DIR)/integration.out" ] || [ ! -s "$(COVERAGE_DIR)/integration.out" ]; then \
			echo "$(RED)✗ Integration test coverage profile missing or empty$(RESET)"; \
			exit 1; \
		fi; \
		if [ $$integration_exit -ne 0 ]; then exit $$integration_exit; fi
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


.PHONY: coverage-threshold-check
## coverage-threshold-check: Check per-package coverage against 90% threshold (issue #703)
## Blocking: for local use, and the future CI gate once #704/#705/#706 close.
coverage-threshold-check: coverage-packages
	@bash scripts/check-coverage.sh 90 "$(COVERAGE_DIR)/all-packages.out"

.PHONY: coverage-threshold-report
## coverage-threshold-report: Report per-package coverage (non-blocking, for CI)
coverage-threshold-report:
	@if [ ! -f "$(COVERAGE_FILE)" ]; then \
		echo "$(YELLOW)⚠ Coverage file not found. Skipping per-package report.$(RESET)"; \
		exit 0; \
	fi
	@echo "$(CYAN)→ Per-package coverage report (90% threshold)...$(RESET)"
	@echo ""
	@$(MAKE) --no-print-directory coverage-packages || true
	@bash scripts/check-coverage.sh 90 "$(COVERAGE_DIR)/all-packages.out" || true

# ==============================================================================
# Package-Specific Unit Tests
# ==============================================================================

.PHONY: test-backend
## test-backend: Run backend package unit tests
test-backend:
	@echo "$(CYAN)→ Testing backend package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/backend/...

.PHONY: test-server
## test-server: Run server package unit tests
test-server:
	@echo "$(CYAN)→ Testing server package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/server/...

.PHONY: test-server-fips
## test-server-fips: Run server package unit tests in a FIPS build (approved bootstrap suite only)
# The `fips` build tag is what go-truststrap keys its X25519 refusal on, so this
# is the only lane that compiles the FIPS half of the bootstrap listener: Noise_NK
# is unavailable and TSBOOT1_P256_AESGCM_SHA256 is the only suite offered. Without
# it the approved handshake is never executed by any target (go-xkms#269).
test-server-fips:
	@echo "$(CYAN)→ Testing server package (FIPS build)...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS_FIPS) ./pkg/server/...

.PHONY: test-trust-bootstrap-fips
## test-trust-bootstrap-fips: Run the trust-bootstrap dispatch tests in a FIPS build (client offers the approved suite only)
# The client half of go-xkms#269: with Noise_NK compiled out, Fetch(ModeNoise)
# must skip the Curve25519 key and complete a real P-256 handshake against a
# real listener. Only this lane compiles that refusal into the dispatch tests.
test-trust-bootstrap-fips:
	@echo "$(CYAN)→ Testing trust/bootstrap package (FIPS build)...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS_FIPS) ./pkg/trust/bootstrap/...

.PHONY: test-config
## test-config: Run config package unit tests
test-config:
	@echo "$(CYAN)→ Testing config package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/config/...

.PHONY: test-xkms
## test-xkms: Run xkms package unit tests
test-xkms:
	@echo "$(CYAN)→ Testing xkms package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/xkms/...

.PHONY: test-types
## test-types: Run types package unit tests
test-types:
	@echo "$(CYAN)→ Testing types package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/types/...

.PHONY: test-rest
## test-rest: Run REST API package unit tests
test-rest:
	@echo "$(CYAN)→ Testing REST API package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/api/rest/...

.PHONY: test-mcp
## test-mcp: Run MCP API package unit tests
test-mcp:
	@echo "$(CYAN)→ Testing MCP API package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/api/mcp/...

.PHONY: test-grpc
## test-grpc: Run gRPC API package unit tests
test-grpc:
	@echo "$(CYAN)→ Testing gRPC API package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/api/grpc/...

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

.PHONY: test-image
## test-image: Run container image signing package unit tests
test-image:
	@echo "$(CYAN)→ Testing image package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/image/...

.PHONY: test-attestation
## test-attestation: Run attestation package unit tests (invariants, android, dice)
test-attestation:
	@echo "$(CYAN)→ Testing attestation packages...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/attestation/...

.PHONY: test-dice
## test-dice: Run TCG DICE attestation package unit tests
test-dice:
	@echo "$(CYAN)→ Testing DICE attestation package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/attestation/dice/...

.PHONY: bench-dice
## bench-dice: Run TCG DICE attestation package benchmarks
bench-dice:
	@echo "$(CYAN)→ Benchmarking DICE attestation package...$(RESET)"
	@$(GO) test $(TAG_FLAGS) ./pkg/attestation/dice/... -bench=. -benchmem -run=^$$

.PHONY: coverage-dice
## coverage-dice: Generate coverage report for the TCG DICE attestation package
coverage-dice:
	@echo "$(CYAN)→ Generating DICE attestation coverage...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GO) test $(TAG_FLAGS) ./pkg/attestation/dice/... -coverprofile=$(COVERAGE_DIR)/dice.out -covermode=atomic
	@$(GO) tool cover -html=$(COVERAGE_DIR)/dice.out -o $(COVERAGE_DIR)/dice-coverage.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/dice.out > $(COVERAGE_DIR)/dice.txt
	@TOTAL=$$(grep '^total:' $(COVERAGE_DIR)/dice.txt | awk '{print $$NF}'); \
	echo "$(CYAN)dice coverage: $${TOTAL}$(RESET)"

.PHONY: coverage-attestation
## coverage-attestation: Generate coverage report for the attestation packages
coverage-attestation:
	@echo "$(CYAN)→ Generating attestation coverage...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GO) test $(TAG_FLAGS) ./pkg/attestation/... -coverprofile=$(COVERAGE_DIR)/attestation.out -covermode=atomic
	@$(GO) tool cover -html=$(COVERAGE_DIR)/attestation.out -o $(COVERAGE_DIR)/attestation-coverage.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/attestation.out > $(COVERAGE_DIR)/attestation.txt
	@TOTAL=$$(grep '^total:' $(COVERAGE_DIR)/attestation.txt | awk '{print $$NF}'); \
	echo "$(CYAN)attestation coverage: $${TOTAL}$(RESET)"

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

.PHONY: test-ecpoint
## test-ecpoint: Run EC point reconstruction package unit tests
test-ecpoint:
	@echo "$(CYAN)→ Testing EC point package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/crypto/ecpoint/...

.PHONY: bench-ecpoint
## bench-ecpoint: Run EC point reconstruction benchmarks
bench-ecpoint:
	@echo "$(CYAN)→ Running EC point benchmarks...$(RESET)"
	@$(GOTEST) -bench=. -benchmem ./pkg/crypto/ecpoint/...

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

.PHONY: test-avr
## test-avr: Run AVR device backend unit tests
test-avr:
	@echo "$(CYAN)→ Testing AVR device backend...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/backend/avr/...

.PHONY: bench-avr
## bench-avr: Run AVR device backend benchmarks
bench-avr:
	@echo "$(CYAN)→ Benchmarking AVR device backend...$(RESET)"
	@$(GO) test $(TAG_FLAGS) ./pkg/backend/avr/... -bench=. -benchmem -run=^$$

.PHONY: coverage-avr
## coverage-avr: Generate coverage report for the AVR device backend
coverage-avr:
	@echo "$(CYAN)→ Generating AVR device backend coverage...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GO) test $(TAG_FLAGS) ./pkg/backend/avr/... -coverprofile=$(COVERAGE_DIR)/avr.out -covermode=atomic
	@$(GO) tool cover -html=$(COVERAGE_DIR)/avr.out -o $(COVERAGE_DIR)/avr-coverage.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/avr.out > $(COVERAGE_DIR)/avr.txt
	@TOTAL=$$(grep '^total:' $(COVERAGE_DIR)/avr.txt | awk '{print $$NF}'); \
	echo "$(CYAN)avr coverage: $${TOTAL}$(RESET)"

.PHONY: test-software
## test-software: Run unified software backend unit tests
test-software:
	@echo "$(CYAN)→ Testing unified software backend...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/backend/software/...


.PHONY: test-quantum
## test-quantum: Run all quantum-safe cryptography unit tests (backend, software routing, PKCS11, CA)
test-quantum: test-quantum-backend test-quantum-software test-quantum-pkcs11 test-quantum-pkcs11-module test-quantum-ca test-quantum-primitives
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
	@$(GO) test -v -tags="$(call go_tags,pkcs11 codec_cbor codec_json codec_msgpack tpm_simulator)" ./pkg/backend/pkcs11/... -run "Quantum|MLDSA|MLKEM"

.PHONY: test-quantum-pkcs11-module
## test-quantum-pkcs11-module: Run PKCS11 module quantum mechanism, crypto, and KEM tests
test-quantum-pkcs11-module:
	@echo "$(CYAN)→ Testing PKCS11 module quantum mechanisms...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/pkcs11/module/... -run "Quantum|MLDSA|MLKEM|Encapsulat"

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

.PHONY: test-dns01
## test-dns01: Run ACME DNS-01 challenge and provider unit tests
test-dns01:
	@echo "$(CYAN)→ Testing DNS-01 challenge providers...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/acme/challenges/dns-01/...

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

.PHONY: test-rand-tpm2
## test-rand-tpm2: Run crypto/rand package unit tests with TPM2 simulator support
test-rand-tpm2:
	@echo "$(CYAN)→ Testing crypto/rand package with TPM2 simulator...$(RESET)"
	@$(GO) test -tags=$(call go_tags,) $(TEST_FLAGS) ./pkg/crypto/rand/...

.PHONY: test-rand-all
## test-rand-all: Run all crypto/rand unit tests (software + TPM2)
test-rand-all: test-rand test-rand-tpm2
	@echo "$(GREEN)✓ All crypto/rand unit tests complete$(RESET)"

# pkg/tpm2 on the in-process TPM simulator.
#
# test-go greps `pkg/tpm2$` OUT of its package list, so nothing in this
# package -- the TCG specification vectors, the CSR structure test, the
# provisioning fail-closed tests -- runs under `make test`. These targets are
# the single entry point for the suite, and the CI job `tpm2-simulator` calls
# the first one. The simulator is cgo (go-tpm-tools links -lcrypto), so the
# suite runs without -race: measured at ~90 s on a workstation without it, and
# the 20-minute timeout bounds a loaded runner rather than a healthy run.
TPM2_SIMULATOR_TAGS := codec_cbor codec_json codec_msgpack tpm_simulator
TPM2_SIMULATOR_TIMEOUT ?= 20m

.PHONY: test-tpm2-simulator
## test-tpm2-simulator: Run the pkg/tpm2 unit suite against the TPM simulator
test-tpm2-simulator:
	@echo "$(CYAN)→ Testing tpm2 package on the simulator...$(RESET)"
	@$(GO) test -timeout $(TPM2_SIMULATOR_TIMEOUT) -tags="$(call go_tags,$(TPM2_SIMULATOR_TAGS))" ./pkg/tpm2/...
	@echo "$(GREEN)✓ tpm2 simulator tests passed$(RESET)"

.PHONY: coverage-tpm2-simulator
## coverage-tpm2-simulator: Generate a pkg/tpm2 coverage report from the simulator suite
coverage-tpm2-simulator:
	@echo "$(CYAN)→ Generating tpm2 simulator coverage report...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GO) test -timeout $(TPM2_SIMULATOR_TIMEOUT) -tags="$(call go_tags,$(TPM2_SIMULATOR_TAGS))" \
		-coverprofile=$(COVERAGE_DIR)/tpm2-simulator.raw -covermode=atomic ./pkg/tpm2/...
	@grep -v -E "/mocks/|_test\.go" $(COVERAGE_DIR)/tpm2-simulator.raw > $(COVERAGE_DIR)/tpm2-simulator.out
	@$(GO) tool cover -html=$(COVERAGE_DIR)/tpm2-simulator.out -o $(COVERAGE_DIR)/tpm2-simulator.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/tpm2-simulator.out | tail -1
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/tpm2-simulator.html$(RESET)"

.PHONY: bench-tpm2-simulator
## bench-tpm2-simulator: Run the pkg/tpm2 benchmarks against the TPM simulator
bench-tpm2-simulator:
	@echo "$(CYAN)→ Running tpm2 simulator benchmarks...$(RESET)"
	@$(GO) test -timeout $(TPM2_SIMULATOR_TIMEOUT) -tags="$(call go_tags,$(TPM2_SIMULATOR_TAGS))" -bench=. -benchmem -run=^$$ ./pkg/tpm2/...

# Packages that only exist, or only compile their production code paths,
# behind the `pkcs11` build tag (issue #703): pkg/backend/pkcs11,
# pkg/factor/pkcs11 and pkg/pivcert/pkcs11 have no buildable files at all
# without it, and pkg/crypto/rand / pkg/storage/hardware each carry a
# pkcs11.go alongside a `!pkcs11` stub, so the tagged build is the only way
# to exercise the real implementation rather than the stub. None of this
# needs a physical HSM: the suite runs against SoftHSM2 (miekg/pkcs11 dlopens
# the module at runtime), which the `test` CI job already installs as an
# unconditional cgo dependency of the module graph.
PKCS11_TAGGED_TAGS := $(TEST_TAGS) pkcs11
PKCS11_TAGGED_PKGS := ./pkg/backend/pkcs11/... ./pkg/pkcs11strategy/... ./pkg/embeddednode/... ./pkg/factor/pkcs11/... ./pkg/pivcert/pkcs11/... ./pkg/crypto/rand/... ./pkg/storage/hardware/...

.PHONY: test-pkcs11-tagged
## test-pkcs11-tagged: Run the pkcs11-tag-gated unit suites against SoftHSM2
test-pkcs11-tagged:
	@echo "$(CYAN)→ Testing pkcs11-tagged packages...$(RESET)"
	@CGO_ENABLED=1 $(GO) test -timeout 20m -tags="$(call go_tags,$(PKCS11_TAGGED_TAGS))" $(PKCS11_TAGGED_PKGS)
	@echo "$(GREEN)✓ pkcs11-tagged tests passed$(RESET)"

.PHONY: coverage-pkcs11-tagged
## coverage-pkcs11-tagged: Generate a coverage report for the pkcs11-tag-gated packages
coverage-pkcs11-tagged:
	@echo "$(CYAN)→ Generating pkcs11-tagged coverage report...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@CGO_ENABLED=1 $(GO) test -timeout $(UNIT_TEST_TIMEOUT) -tags="$(call go_tags,$(PKCS11_TAGGED_TAGS))" \
		-coverprofile=$(COVERAGE_DIR)/pkcs11-tagged.raw -covermode=atomic $(PKCS11_TAGGED_PKGS)
	@grep -v -E "/mocks/|_test\.go" $(COVERAGE_DIR)/pkcs11-tagged.raw > $(COVERAGE_DIR)/pkcs11-tagged.out
	@$(GO) tool cover -html=$(COVERAGE_DIR)/pkcs11-tagged.out -o $(COVERAGE_DIR)/pkcs11-tagged.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/pkcs11-tagged.out | tail -1
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/pkcs11-tagged.html$(RESET)"

.PHONY: coverage-packages
## coverage-packages: Merge every per-package coverage lane (main unit lane,
## tpm2 simulator, pkcs11-tagged, GODEBUG=fips140=on for pkg/crypto/fips) into one profile (issue #703). Requires
## $(COVERAGE_FILE) to already exist -- run `make coverage` (or `test-go`)
## first; this target only runs the lanes `test-go` cannot reach itself.
coverage-packages: coverage-tpm2-simulator coverage-pkcs11-tagged coverage-fips
	@if [ ! -f "$(COVERAGE_FILE)" ]; then \
		echo "$(RED)✗ $(COVERAGE_FILE) not found -- run 'make coverage' first$(RESET)"; \
		exit 1; \
	fi
	@mkdir -p $(COVERAGE_DIR)
	@echo "mode: atomic" > $(COVERAGE_DIR)/all-packages.out
	@tail -n +2 $(COVERAGE_FILE) >> $(COVERAGE_DIR)/all-packages.out
	@tail -n +2 $(COVERAGE_DIR)/tpm2-simulator.out >> $(COVERAGE_DIR)/all-packages.out
	@tail -n +2 $(COVERAGE_DIR)/pkcs11-tagged.out >> $(COVERAGE_DIR)/all-packages.out
	@tail -n +2 $(COVERAGE_DIR)/fips.out >> $(COVERAGE_DIR)/all-packages.out
	@echo "$(GREEN)✓ Merged coverage profile: $(COVERAGE_DIR)/all-packages.out$(RESET)"

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
	@$(GO) test -tags=$(call go_tags,awskms) $(TEST_FLAGS) ./pkg/backend/awskms/... -run "Test.*Import|Test.*Export|Test.*Wrap"
	@echo "$(CYAN)→ Testing GCP KMS backend import/export...$(RESET)"
	@$(GO) test -tags=$(call go_tags,gcpkms) $(TEST_FLAGS) ./pkg/backend/gcpkms/... -run "Test.*Import|Test.*Export|Test.*Wrap"
	@echo "$(CYAN)→ Testing TPM2 backend import/export...$(RESET)"
	@$(GO) test -tags=$(call go_tags,) $(TEST_FLAGS) ./pkg/tpm2/... -run "Test.*Import|Test.*Export"
	@echo "$(CYAN)→ Testing PKCS#11 backend import/export...$(RESET)"
	@$(GO) test -tags=$(call go_tags,pkcs11) $(TEST_FLAGS) ./pkg/backend/pkcs11/... -run "Test.*Import|Test.*Export|TestCapabilities"


.PHONY: test-sdk-go
## test-sdk-go: Run Go SDK unit tests (separate module at sdk/go)
test-sdk-go:
	@echo "$(CYAN)→ Testing Go SDK package...$(RESET)"
	@cd sdk/go && $(GO) test $(TEST_FLAGS) ./...
	@echo "$(GREEN)✓ Go SDK unit tests complete$(RESET)"

.PHONY: test-sdk-transport
## test-sdk-transport: Run Go SDK REST transport unit tests (tenant)
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
# Auth, Audit, and CLI Unit Tests
#
# Authz is not a separate package: pkg/auth/authorize.go delegates every
# resource:action decision to the hosted qrdb node's RBAC service, so
# test-auth already covers it. RBAC and the user/identity model are owned
# by go-qrdb (consumed only via go-qrdb/sdk/go) and have no local package
# here to test — see docs/00-ownership-and-sdk-boundary.md in the handbook.
# ==============================================================================

.PHONY: test-auth
## test-auth: Run auth package unit tests
test-auth:
	@echo "$(CYAN)→ Testing auth package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/auth/...
	@echo "$(GREEN)✓ Auth package tests complete$(RESET)"

.PHONY: coverage-auth
## coverage-auth: Generate coverage report for the auth package
coverage-auth:
	@echo "$(CYAN)→ Generating coverage report for auth package...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/auth.out -covermode=atomic ./pkg/auth/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/auth.out -o $(COVERAGE_DIR)/auth.html
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/auth.html$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/auth.out | grep total

.PHONY: test-audit
## test-audit: Run audit package unit tests
test-audit:
	@echo "$(CYAN)→ Testing audit package...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/audit/...
	@echo "$(GREEN)✓ Audit package tests complete$(RESET)"

.PHONY: coverage-audit
## coverage-audit: Generate coverage report for the audit package
coverage-audit:
	@echo "$(CYAN)→ Generating coverage report for audit package...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/audit.out -covermode=atomic ./pkg/audit/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/audit.out -o $(COVERAGE_DIR)/audit.html
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/audit.html$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/audit.out | grep total

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

.PHONY: coverage-seal
## coverage-seal: Generate coverage report for seal package
coverage-seal:
	@echo "$(CYAN)→ Generating coverage report for seal package...$(RESET)"
	@mkdir -p $(COVERAGE_DIR)
	@$(GOTEST) -race -coverprofile=$(COVERAGE_DIR)/seal.out -covermode=atomic ./pkg/seal/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/seal.out -o $(COVERAGE_DIR)/seal.html
	@echo "$(GREEN)✓ Coverage report: $(COVERAGE_DIR)/seal.html$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/seal.out | grep total

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

# integration-test-pkcs11 is the BACKEND lane (xkms as a client of SoftHSM);
# integration-test-pkcs11-module-all is the MODULE lane (the .so xkms ships to
# other applications), and the two prove nothing about each other. The module
# lane used to be represented here by integration-test-pkcs11-conformance alone,
# which left the C ABI and the whole OpenSSL/OpenSSH interop surface out of every
# default run -- the exact surface real callers reach the module through.
#
# integration-test-cluster stays out of the default run: its three Raft nodes
# cannot initialize their barriers until each node can be initialized without
# running its own first boot, against a shared bootstrap CA. Run it on its own.
integration-test: clean-test-containers integration-test-software integration-test-pkcs8 integration-test-pkcs11 integration-test-pkcs11-barrier integration-test-pkcs11-module-all integration-test-tpm2 integration-test-challenges integration-test-awskms integration-test-gcpkms integration-test-azurekv integration-test-vault integration-test-storage integration-test-utils integration-test-quantum integration-test-frost integration-test-webauthn integration-test-fido2 integration-test-cli integration-test-api-all integration-test-sdk-go integration-test-sshagent integration-test-initceremony integration-test-bootstrap
	@echo "$(GREEN)$(BOLD)✓ All integration tests complete!$(RESET)"

.PHONY: clean-run-images
## clean-run-images: Remove the images this CI run tagged (no-op for local builds)
# `docker image prune -f` only reaps UNTAGGED images, so the per-run tags
# (XKMS_IMAGE_TAG) would otherwise pile up a full set of images on the runner
# host every single run. Unlike the host-wide `docker image prune -a` this
# replaces, the selection is bounded twice: the repository must be one this
# harness builds (XKMS_IMAGE_REPOS) and the tag must be this run's. Either
# bound alone is not ownership -- an unrelated repository on the host can hold
# any tag, including a numeric run id that matches ours, and can build an
# image name that matches one of ours under a different tag.
#
# Off CI, XKMS_IMAGE_TAG is empty and the images carry the shared local tags
# (:latest, :dev). Removing those would throw away a developer's build cache,
# so this deliberately does nothing.
clean-run-images:
	@if [ -z "$(XKMS_IMAGE_TAG)" ]; then \
		echo "$(CYAN)→ Local image tags; nothing to remove$(RESET)"; \
	else \
		refs=""; \
		for repo in $(XKMS_IMAGE_REPOS); do \
			refs="$$refs $$(docker images --filter=reference="$$repo:$(XKMS_IMAGE_TAG)" --format '{{.Repository}}:{{.Tag}}' 2>/dev/null || true)"; \
		done; \
		if [ -n "$$(echo $$refs)" ]; then docker rmi -f $$refs >/dev/null 2>&1 || true; fi; \
		echo "$(GREEN)✓ Removed this run's images tagged :$(XKMS_IMAGE_TAG)$(RESET)"; \
	fi

.PHONY: clean-test-containers
## clean-test-containers: Clean up Docker containers from previous test runs
# Failures are NOT swallowed (go-xkms#2): the script exits non-zero when a
# compose project it owns could not be torn down, which on a shared CI host
# means this repo's containers and volumes are still there. Its chatter goes
# to the log file; anything it wrote to stderr, plus that log, is printed
# when it fails.
clean-test-containers:
	@echo "$(CYAN)→ Cleaning up test containers...$(RESET)"
	@# COMPOSE_RUN_ID is passed explicitly so the script cannot compute a
	@# different project name than the Makefile did and silently clean nothing.
	@#
	@# Output goes to a log and a failure FAILS this target (issue #2's shape,
	@# kept over issue #8's `>/dev/null 2>&1 || true`). Cleanup runs BEFORE the
	@# suite, so swallowing its exit code means the suite then runs against
	@# whatever the previous run left behind and reports that as a test result.
	@mkdir -p $(BUILD_DIR)
	@if COMPOSE_RUN_ID=$(COMPOSE_RUN_ID) bash test/scripts/clean-test-containers.sh >$(BUILD_DIR)/clean-test-containers.log 2>&1; then \
		echo "$(GREEN)✓ Test containers cleaned$(RESET)"; \
	else \
		echo "$(RED)✗ Test container cleanup failed:$(RESET)"; \
		cat $(BUILD_DIR)/clean-test-containers.log; \
		exit 1; \
	fi

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
	@cd test/integration/storage && $(call compose,storage) down -v >/dev/null 2>&1 || true
	@cd test/integration/storage && trap '$(call compose,storage) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,storage) run --rm test-file
	@echo "$(GREEN)✓ File storage integration tests complete$(RESET)"

.PHONY: integration-test-storage-memory
## integration-test-storage-memory: Run memory storage integration tests
integration-test-storage-memory:
	@echo "$(CYAN)$(BOLD)→ Running memory storage integration tests...$(RESET)"
	@cd test/integration/storage && $(call compose,storage) down -v >/dev/null 2>&1 || true
	@cd test/integration/storage && trap '$(call compose,storage) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,storage) run --rm test-memory
	@echo "$(GREEN)✓ Memory storage integration tests complete$(RESET)"

.PHONY: integration-test-storage-hardware
## integration-test-storage-hardware: Run hardware storage integration tests (PKCS#11 + TPM2)
integration-test-storage-hardware: integration-test-storage-hardware-pkcs11 integration-test-storage-hardware-tpm2
	@echo "$(GREEN)✓ Hardware storage integration tests complete$(RESET)"

.PHONY: integration-test-yubikey
## integration-test-yubikey: Run YubiKey hardware integration tests (requires physical YubiKey in default state)
integration-test-yubikey:
	@echo "WARNING: This will reset the first connected YubiKey to factory defaults"
	go test -tags="$(call go_tags,pkcs11 yubikey_hardware)" -v -count=1 ./pkg/backend/pkcs11/ -run TestYubiKey

.PHONY: integration-test-storage-hardware-pkcs11
## integration-test-storage-hardware-pkcs11: Run PKCS#11 hardware storage tests
integration-test-storage-hardware-pkcs11:
	@echo "$(CYAN)$(BOLD)→ Running PKCS#11 hardware storage tests...$(RESET)"
	@cd test/integration/storage && $(call compose,storage) down -v >/dev/null 2>&1 || true
	@cd test/integration/storage && trap '$(call compose,storage) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,storage) run --rm test-hardware-pkcs11
	@echo "$(GREEN)✓ PKCS#11 hardware storage tests complete$(RESET)"

.PHONY: integration-test-storage-hardware-tpm2
## integration-test-storage-hardware-tpm2: Run TPM2 hardware storage tests
integration-test-storage-hardware-tpm2:
	@echo "$(CYAN)$(BOLD)→ Running TPM2 hardware storage tests...$(RESET)"
	@cd test/integration/storage && $(call compose,storage) down -v >/dev/null 2>&1 || true
	@cd test/integration/storage && $(call compose,storage) up -d tpm-simulator
	@sleep 3
	@cd test/integration/storage && trap '$(call compose,storage) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,storage) run --rm test-hardware-tpm2
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
	go test -v -tags='$(call go_tags,hw_integration$(comma)pkcs11$(comma)codec_cbor$(comma)codec_json$(comma)codec_msgpack)' ./test/integration/storage -run TestRealPKCS11Hardware -timeout 15m
	@echo "$(GREEN)✓ Real PKCS#11 hardware storage tests complete$(RESET)"

.PHONY: integration-test-hw-storage-tpm2
## integration-test-hw-storage-tpm2: Run real TPM2 hardware storage tests (requires physical TPM)
integration-test-hw-storage-tpm2:
	@echo "$(CYAN)$(BOLD)→ Running real TPM2 hardware storage tests...$(RESET)"
	@echo "$(YELLOW)NOTE: This requires real TPM2 hardware (/dev/tpm0 or /dev/tpmrm0)$(RESET)"
	go test -v -tags='$(call go_tags,hw_integration$(comma)codec_cbor$(comma)codec_json$(comma)codec_msgpack)' ./test/integration/storage -run TestRealTPM2Hardware -timeout 15m
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
	@$(GO) test -v -tags=$(call go_tags,integration) -coverprofile=$(COVERAGE_DIR)/file-storage.out -covermode=atomic \
		./pkg/storage/file/... ./test/integration/storage/... -run 'TestFileStorage'
	@$(GO) tool cover -html=$(COVERAGE_DIR)/file-storage.out -o $(COVERAGE_DIR)/file-storage.html
	@echo "$(GREEN)✓ File storage coverage report generated$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/file-storage.out | grep total

.PHONY: coverage-memory-storage
## coverage-memory-storage: Generate memory storage coverage report
coverage-memory-storage:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating memory storage coverage report...$(RESET)"
	@$(GO) test -v -tags=$(call go_tags,integration) -coverprofile=$(COVERAGE_DIR)/memory-storage.out -covermode=atomic \
		./pkg/storage ./test/integration/storage/... -run 'TestMemoryStorage'
	@$(GO) tool cover -html=$(COVERAGE_DIR)/memory-storage.out -o $(COVERAGE_DIR)/memory-storage.html
	@echo "$(GREEN)✓ Memory storage coverage report generated$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/memory-storage.out | grep total

.PHONY: coverage-hardware-storage
## coverage-hardware-storage: Generate hardware storage coverage report
coverage-hardware-storage:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating hardware storage coverage report...$(RESET)"
	@$(GO) test -v -tags='$(call go_tags,integration$(comma)pkcs11)' -coverprofile=$(COVERAGE_DIR)/hardware-storage.out -covermode=atomic \
		./pkg/storage/hardware/... ./test/integration/storage/... -run 'TestHardwareStorage'
	@$(GO) tool cover -html=$(COVERAGE_DIR)/hardware-storage.out -o $(COVERAGE_DIR)/hardware-storage.html
	@echo "$(GREEN)✓ Hardware storage coverage report generated$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/hardware-storage.out | grep total

# ==============================================================================
# Cloud Service Emulator Management
# ==============================================================================

EMULATOR_COMPOSE := $(call compose,emulators) -f docker-compose.emulators.yml

.PHONY: emulator-start
## emulator-start: Start cloud service emulators
emulator-start:
	@bash test/scripts/setup-azure-emulator-certs.sh
	@$(EMULATOR_COMPOSE) up -d
	@sleep 15

.PHONY: emulator-stop
## emulator-stop: Stop and remove emulator containers
# `compose down` on the two projects this target owns, and nothing more.
#
# This used to follow up with `docker stop/rm $(docker ps -q --filter name=X)`
# for floci/xkms/azure/gcp/vault. A --filter name= is a SUBSTRING match across
# every container on the host, so "name=xkms" matched -- and killed -- every
# container of every other job on a shared runner, this suite's included.
# `down` scoped to this run's project removes exactly what this run created.
emulator-stop:
	@$(EMULATOR_COMPOSE) down -v --remove-orphans 2>/dev/null || true
	@cd $(API_TEST_DIR) && $(call compose,api) down -v --remove-orphans 2>/dev/null || true

.PHONY: emulator-restart
## emulator-restart: Restart emulators
emulator-restart: emulator-stop emulator-start

.PHONY: emulator-status
## emulator-status: Check emulator health
emulator-status:
	@$(EMULATOR_COMPOSE) ps
	@echo ""
	@curl -sf http://localhost:4566/_floci/health >/dev/null 2>&1 && echo "Floci (AWS): Running" || echo "Floci (AWS): Not responding"
	@curl -sf http://localhost:4588/health >/dev/null 2>&1 && echo "Floci (GCP): Running" || echo "Floci (GCP): Not responding"
	@curl -s -k https://localhost:4997/health >/dev/null 2>&1 && echo "Azure KV: Running" || echo "Azure KV: Not responding"

.PHONY: emulator-logs
## emulator-logs: View emulator logs
emulator-logs:
	@$(EMULATOR_COMPOSE) logs -f

.PHONY: emulator-clean
## emulator-clean: Stop emulators and clean data
emulator-clean: emulator-stop
	@rm -rf .azure-emulator

# ==============================================================================
# Package-Specific Integration Tests
# ==============================================================================

.PHONY: integration-test-software
## integration-test-software: Run unified software backend integration tests (runs in devcontainer)
integration-test-software:
	$(call run_in_devcontainer,$(GO) test -v -tags=$(call go_tags,integration) ./pkg/backend/software/... -timeout 5m,integration-test-software)

.PHONY: integration-test-symmetric
## integration-test-symmetric: Run symmetric backend integration tests (runs in devcontainer)
integration-test-symmetric:
	$(call run_in_devcontainer,$(GO) test -v -tags=$(call go_tags,integration) ./pkg/keyprovider/symmetric/... -timeout 5m,integration-test-symmetric)

.PHONY: integration-test-pkcs8
## integration-test-pkcs8: Run PKCS8 asymmetric backend integration tests
integration-test-pkcs8:
	@echo "$(CYAN)$(BOLD)→ Running PKCS8 integration tests...$(RESET)"
	@cd test/integration/pkcs8 && $(call compose,pkcs8) down -v >/dev/null 2>&1 || true
	@cd test/integration/pkcs8 && trap '$(call compose,pkcs8) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,pkcs8) run --build --rm test
	@echo "$(GREEN)✓ PKCS8 integration tests complete$(RESET)"

.PHONY: integration-test-pkcs11-backend integration-test-pkcs11
## integration-test-pkcs11-backend: Run the PKCS#11 BACKEND (core library) tests against SoftHSM
## integration-test-pkcs11: Alias of integration-test-pkcs11-backend
# This exercises pkg/backend/pkcs11 -- xkms acting as a PKCS#11 CLIENT of an HSM.
# It is a different layer from integration-test-pkcs11-module-all, which tests
# the PKCS#11 module xkms PROVIDES to other applications. Keeping the two apart
# matters: a green run of one says nothing about the other.
integration-test-pkcs11: integration-test-pkcs11-backend
integration-test-pkcs11-backend:
	@echo "$(CYAN)$(BOLD)→ Running PKCS11/SoftHSM integration tests...$(RESET)"
	@cd test/integration/pkcs11 && $(call compose,pkcs11) down -v >/dev/null 2>&1 || true
	@cd test/integration/pkcs11 && trap '$(call compose,pkcs11) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,pkcs11) run --build --rm test
	@echo "$(GREEN)✓ PKCS11 integration tests complete$(RESET)"

.PHONY: integration-test-pkcs11-barrier
## integration-test-pkcs11-barrier: Run the TPM-sealed PKCS#11 barrier PIN reboot test (SoftHSM + swtpm)
# xkmsd seals the token PIN under the Platform SRK, restarts against the same
# swtpm and must unseal unattended, then must refuse to start once the
# platform PCR moves. The swtpm is the compose service, never the
# devcontainer's TPM. compose run waits for the simulator's healthcheck.
integration-test-pkcs11-barrier:
	@echo "$(CYAN)$(BOLD)→ Running TPM-sealed PKCS#11 barrier PIN integration tests (SoftHSM + swtpm)...$(RESET)"
	@$(MAKE) --no-print-directory stage-gomodauth
	@cd test/integration/pkcs11/barrier && $(call compose,pkcs11-barrier) down -v >/dev/null 2>&1 || true
	@cd test/integration/pkcs11/barrier && trap '$(call compose,pkcs11-barrier) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,pkcs11-barrier) run --build --rm test \
		go test -v -count=1 -tags='$(call go_tags,integration pkcs11 pkcs11_barrier codec_cbor codec_json codec_msgpack)' -timeout 15m \
		./test/integration/pkcs11/barrier/...
	@echo "$(GREEN)✓ TPM-sealed PKCS#11 barrier PIN integration tests complete$(RESET)"

.PHONY: integration-test-pkcs11-module
## integration-test-pkcs11-module: Run PKCS#11 module multi-protocol integration tests (runs in devcontainer with xkms-server)
integration-test-pkcs11-module:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_PKCS11_ALLOW_WEAK_HASH_SIGNING=true XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) $(GO) test -v -tags='$(call go_tags,integration)' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT),integration-test-pkcs11-module)

.PHONY: integration-test-logins
## integration-test-logins: Run the login-plane verification matrix (mTLS, PIV, FIDO2) against a real xkmsd (runs in devcontainer with xkms-server)
# Mirrors integration-test-pkcs11-module's use of run_with_server: it starts
# the compose xkms-server and publishes its CA + first-boot admin mTLS
# credential to /tmp/xkms via build/docker/devcontainer/scripts/ensure-server-ca.sh,
# which testutil.go in test/integration/logins reads. The xkey CLI is built
# fresh (plain codec_json tag - no GUI/hardware tags needed for this suite)
# and exported as XKEY_CLI_BIN for the fido2 leg, which drives it as a real
# subprocess ("xkey auth register" / "xkey auth login") against a headless
# "xkey fido2 --require-touch=false --pin=false" virtual authenticator (the
# argv is VirtualAuthenticatorArgv in test/integration/logins/argv.go, and
# xkey/cmd/xkey/cmd's unit tests check it against the registered flags). That
# authenticator opens a uhid device, so the suite runs under sudo, the same
# requirement integration-test-xkey-ctap has for the same reason.
integration-test-logins:
	$(call run_with_server,mkdir -p build/bin && cd xkey && /usr/local/go/bin/go build -buildvcs=false -tags='$(call go_tags,codec_json)' -o ../build/bin/xkey ./cmd/xkey && cd .. && XKEY_CLI_BIN=$(DEVCONTAINER_REPO)/build/bin/xkey sudo -E /usr/local/go/bin/go test -v -tags='$(call go_tags,integration$(comma)logins)' ./test/integration/logins/... -timeout 10m,integration-test-logins)

.PHONY: integration-test-logins-quicbaas
## integration-test-logins-quicbaas: Login matrix including the quicbaasd leg (host-invoked; starts the compose quicbaas-server)
# Starts the quicbaas-server fixture (compose profile "quicbaas", built from
# the sibling go-quicbaas working tree with the gomodauth secret), publishes
# its first-boot admin mTLS credential into build/quicbaas-fixture (the
# fixture's /data volume is not mounted into the devcontainer, so the host
# copies it through the workspace), fetches the fixture's CA over its public
# /v1/ca/bootstrap route, and runs the same suite as integration-test-logins
# with QUICBAAS_REST_URL set so targets() adds the quicbaasd rows.
integration-test-logins-quicbaas:
	@echo "$(CYAN)$(BOLD)→ Starting quicbaas-server fixture...$(RESET)"
	@$(MAKE) --no-print-directory stage-gomodauth
	$(DOCKER_COMPOSE) --profile quicbaas up -d --build --wait quicbaas-server
	@echo "$(CYAN)$(BOLD)→ Publishing quicbaasd admin credential to build/quicbaas-fixture...$(RESET)"
	@mkdir -p build/quicbaas-fixture
	@# Resolve the container by compose SERVICE name, never by a fixed
	@# container_name: the project is namespaced per run, so this container is
	@# `<project>-quicbaas-server-1` and no two jobs can address each other's.
	@cid=$$($(DOCKER_COMPOSE) --profile quicbaas ps -q quicbaas-server); \
	[ -n "$$cid" ] || { echo "$(RED)✗ quicbaas-server is not running$(RESET)"; exit 1; }; \
	ok=""; for i in $$(seq 1 30); do \
		if docker cp $$cid:/data/admin/admin.crt build/quicbaas-fixture/admin.crt 2>/dev/null && \
		   docker cp $$cid:/data/admin/admin.key build/quicbaas-fixture/admin.key 2>/dev/null && \
		   docker cp $$cid:/data/certs/ca-chain.crt build/quicbaas-fixture/ca.crt 2>/dev/null; then ok=1; break; fi; \
		sleep 2; \
	done; [ -n "$$ok" ] || { echo "$(RED)✗ quicbaasd first boot never published /data/admin + /data/certs$(RESET)"; docker logs --tail 40 $$cid; exit 1; }
	@chmod 0600 build/quicbaas-fixture/admin.key
	$(call run_with_server,mkdir -p build/bin /tmp/quicbaas && cp $(DEVCONTAINER_REPO)/build/quicbaas-fixture/ca.crt /tmp/quicbaas/ca.crt && cp $(DEVCONTAINER_REPO)/build/quicbaas-fixture/admin.crt /tmp/quicbaas/admin.crt && cp $(DEVCONTAINER_REPO)/build/quicbaas-fixture/admin.key /tmp/quicbaas/admin.key && chmod 0600 /tmp/quicbaas/admin.key && bash build/docker/devcontainer/scripts/wait-quicbaas-login-planes.sh && cd xkey && /usr/local/go/bin/go build -buildvcs=false -tags='$(call go_tags,codec_json)' -o ../build/bin/xkey ./cmd/xkey && cd .. && XKEY_CLI_BIN=$(DEVCONTAINER_REPO)/build/bin/xkey QUICBAAS_REST_URL=https://quicbaas-server:8443 sudo -E /usr/local/go/bin/go test -v -tags='$(call go_tags,integration$(comma)logins)' ./test/integration/logins/... -timeout 15m,integration-test-logins-quicbaas)

.PHONY: integration-test-pkcs11-conformance
## integration-test-pkcs11-conformance: Run the OASIS PKCS#11 v3.0 conformance suite (runs in devcontainer with xkms-server)
# The suite lives in test/integration/pkcs11/module/conformance and is guarded
# by `//go:build integration && conformance`, so it only compiles when BOTH
# tags are passed. Without this target nothing ever passed `conformance` and
# the whole OASIS suite was dead code.
# XKMS_PKCS11_ALLOW_WEAK_HASH_SIGNING=true lets the module advertise and perform
# SHA-1 signature generation so the conformance suite can exercise every
# advertised mechanism, matching the daemon's crypto.allow_weak_hashes:true from
# start-test-xkmsd.sh. Production defaults to off (secure); the FIPS conformance
# lane deliberately omits it, and FIPS withholds SHA-1 signing regardless.
integration-test-pkcs11-conformance:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_PKCS11_ALLOW_WEAK_HASH_SIGNING=true XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) $(GO) test -v -tags='$(call go_tags,integration$(comma)conformance)' ./test/integration/pkcs11/module/conformance/... -timeout $(PKCS11_TEST_TIMEOUT),integration-test-pkcs11-conformance)

.PHONY: integration-test-pkcs11-cabi
## integration-test-pkcs11-cabi: Drive the built .so through its C ABI, proving mechanism parameters survive the cgo boundary (runs in devcontainer with xkms-server)
# Every other PKCS#11 suite calls pkg/pkcs11/module directly from Go, which
# skips cmd/pkcs11-module/exports.go entirely. This one dlopen()s the shared
# object and dispatches through the CK_FUNCTION_LIST_3_2 that C_GetInterface
# returns, exactly as a C application does, so a parameter that is accepted at
# the boundary and then dropped is visible.
#
# REFERENCE_PKCS11_MODULE points at SoftHSM2, which the suite drives through the
# same harness to establish what conforming behaviour looks like before calling
# any disagreement a defect. Its token is initialized here because SoftHSM
# refuses to open a slot that was never initialized.
integration-test-pkcs11-cabi: SOFTHSM_CABI_DIR := /tmp/softhsm-cabi
integration-test-pkcs11-cabi:
	$(call run_with_server,mkdir -p $(SOFTHSM_CABI_DIR)/tokens \
		&& printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' $(SOFTHSM_CABI_DIR) > $(SOFTHSM_CABI_DIR)/softhsm2.conf \
		&& SOFTHSM2_CONF=$(SOFTHSM_CABI_DIR)/softhsm2.conf softhsm2-util --show-slots 2>/dev/null | grep -q 'Label:.*cabi-ref' \
		|| SOFTHSM2_CONF=$(SOFTHSM_CABI_DIR)/softhsm2.conf softhsm2-util --init-token --slot 0 --label cabi-ref --so-pin $(PKCS11_SO_PIN) --pin $(PKCS11_PIN) >/dev/null; \
		PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) SOFTHSM2_CONF=$(SOFTHSM_CABI_DIR)/softhsm2.conf REFERENCE_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so REFERENCE_PKCS11_PIN=$(PKCS11_PIN) CGO_ENABLED=1 $(GO) test -v -count=1 -tags='$(call go_tags,integration$(comma)pkcs11_cabi)' ./test/integration/pkcs11/module/cabi/... -timeout $(PKCS11_TEST_TIMEOUT),integration-test-pkcs11-cabi)

.PHONY: integration-test-pkcs11-module-external
## integration-test-pkcs11-module-external: Run the external-view PKCS#11 module checks (shared-library shape, ldd deps, server reachability) via the pkcs11_external tag
integration-test-pkcs11-module-external:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_ALLOW_WEAK_HASH_SIGNING=true XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) $(GO) test -v -tags='$(call go_tags,integration$(comma)pkcs11$(comma)pkcs11_external)' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT),integration-test-pkcs11-module-external)

.PHONY: integration-test-pkcs11-module-unix
## integration-test-pkcs11-module-unix: Run PKCS#11 multi-protocol tests with Unix socket target (runs in devcontainer with xkms-server)
integration-test-pkcs11-module-unix:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) XKMS_PKCS11_TARGET=unix://$(XKMS_UNIX_SOCKET) $(GO) test -v -tags='$(call go_tags,integration)' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT) -run 'TestMultiProtocol',integration-test-pkcs11-module-unix)

.PHONY: integration-test-pkcs11-module-grpc
## integration-test-pkcs11-module-grpc: Run PKCS#11 multi-protocol tests with gRPC target (runs in devcontainer with xkms-server)
integration-test-pkcs11-module-grpc:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) XKMS_PKCS11_TARGET=$(XKMS_GRPC_ADDR_CONTAINER) $(GO) test -v -tags='$(call go_tags,integration)' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT) -run 'TestMultiProtocol',integration-test-pkcs11-module-grpc)

.PHONY: integration-test-pkcs11-module-compat
## integration-test-pkcs11-module-compat: Run PKCS#11 module compatibility tests with pkcs11-tool (runs in devcontainer with xkms-server)
integration-test-pkcs11-module-compat:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage $(GO) test -v -tags='$(call go_tags,integration$(comma)pkcs11$(comma)pkcs11_tool)' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT) -run 'TestPKCS11Tool',integration-test-pkcs11-module-compat)

.PHONY: integration-test-pkcs11-tool
## integration-test-pkcs11-tool: Run comprehensive pkcs11-tool integration tests (runs in devcontainer with xkms-server)
integration-test-pkcs11-tool:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) $(GO) test -v -tags='$(call go_tags,integration$(comma)pkcs11$(comma)pkcs11_tool)' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT) -run 'TestPKCS11Tool',integration-test-pkcs11-tool)

.PHONY: integration-test-pkcs11-openssl-provider
## integration-test-pkcs11-openssl-provider: Drive the module through OpenSSL 3's pkcs11-provider (runs in devcontainer with xkms-server)
# OpenSSL 3 replaced ENGINEs with providers, so this covers the interface a
# modern caller actually uses. It issues a different C_* sequence than libp11.
integration-test-pkcs11-openssl-provider:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) $(GO) test -v -tags='$(call go_tags,integration$(comma)pkcs11$(comma)pkcs11_tool)' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT) -run 'TestOpenSSLProvider',integration-test-pkcs11-openssl-provider)

.PHONY: integration-test-pkcs11-openssl-schemes
## integration-test-pkcs11-openssl-schemes: Test RSA-PSS, OAEP and TLS handshake through OpenSSL (runs in devcontainer with xkms-server)
# Covers the padding modes and the end-to-end TLS handshake that the engine
# suite does not: a PSS request silently answered with PKCS#1 v1.5 is a defect
# no signature-shape assertion would catch.
integration-test-pkcs11-openssl-schemes:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) $(GO) test -v -tags='$(call go_tags,integration$(comma)pkcs11$(comma)pkcs11_tool)' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT) -run 'TestOpenSSL.*RSAPSS|TestOpenSSL.*RSAOAEP|TestOpenSSL_TLSHandshake',integration-test-pkcs11-openssl-schemes)

.PHONY: integration-test-pkcs11-openssl-backends
## integration-test-pkcs11-openssl-backends: Run the OpenSSL operations against every backend in XKMS_PKCS11_BACKENDS (runs in devcontainer with xkms-server)
# Set XKMS_PKCS11_BACKENDS to a comma-separated list (default: software).
# Verification runs outside the module, so a backend returning the wrong
# signature encoding fails here rather than passing silently.
#
# The default is software because that is the only backend the daemon serving
# this socket can satisfy for every operation. Naming another one costs nothing
# beyond the daemon having it enabled -- the module reads
# XKMS_PKCS11_DEFAULT_BACKEND at C_Initialize, which this target sets per case.
# configs/xkmsd-integration.yaml enables only software: its pkcs11 backend needs
# a credential:// PIN, which a fresh compose volume cannot hold before first
# boot (the comment there says why), so the pkcs11 case below needs a daemon
# whose credential service already holds that PIN:
#
#   make integration-test-pkcs11-openssl-backends XKMS_PKCS11_BACKENDS=software,pkcs11
#
# That run used to be RED on RSA: the pkcs11 backend could not perform a bare
# CKM_RSA_PKCS signature over a caller-supplied DigestInfo, which is exactly
# what the libp11 ENGINE and TLS 1.3 send. signPKCS1v15 prepended a DigestInfo
# prefix chosen from opts.HashFunc() with no case for the NONE hash the module
# asks for. It is FIXED: pkg/backend/pkcs11/signer_rsa.go signs the digest
# verbatim when the requested hash is crypto.Hash(0), matching what
# rsa.SignPKCS1v15 does for the software backend and what
# pkg/xkms/servicer_helpers.go ResolveHash means by "NONE".
#
# Do not reinstate an expected-red note here without re-verifying it. A build
# comment that says a lane is meant to fail is how a genuine failure gets waved
# past, and this one outlived its defect.
#
# tpm2 likewise: configs/xkmsd-integration.yaml enables only software, so the
# daemon must also be given
#   tpm2: {enabled: true, device_path: "tcp://swtpm:2321", use_simulator: true}
# to match the swtpm service the compose stack already runs and the
# TPM_DEVICE_PATH the server container already has.
integration-test-pkcs11-openssl-backends:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) XKMS_PKCS11_BACKENDS=$(XKMS_PKCS11_BACKENDS) $(GO) test -v -tags='$(call go_tags,integration$(comma)pkcs11$(comma)pkcs11_tool)' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT) -run 'TestOpenSSLBackendMatrix',integration-test-pkcs11-openssl-backends)

.PHONY: integration-test-pkcs11-openssl-x509
## integration-test-pkcs11-openssl-x509: Issue certificates with a module-resident key -- CSR, self-signed, and signing somebody else's CSR as a CA
# The rest of the X.509 coverage is self-signed only, where the signing key and
# the certified key are the same object: a module signing over the wrong
# TBSCertificate bytes still produces a certificate that verifies against
# itself. These issue to a separately generated subject key and build the chain
# outside the module, so that coincidence cannot pass.
integration-test-pkcs11-openssl-x509:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) $(GO) test -v -tags='$(call go_tags,integration$(comma)pkcs11$(comma)pkcs11_tool)' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT) -run 'TestOpenSSLProvider_SignsCertificateAsCA|TestOpenSSL_EngineCSR|TestOpenSSL_EngineSelfSignedCertificateVerifies',integration-test-pkcs11-openssl-x509)

.PHONY: integration-test-pkcs11-openssl-engine
## integration-test-pkcs11-openssl-engine: Run the OpenSSL 3 ENGINE lane operations the SSH suite leaves out (PSS, CSR, OAEP, TLS) plus libp11's pinned limitations
# OpenSSL 4.0 removed ENGINE support, so this lane runs against the image's
# OpenSSL 3 build; opensslEngineBinary() selects it and OPENSSL_BIN overrides it.
integration-test-pkcs11-openssl-engine:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) $(GO) test -v -tags='$(call go_tags,integration$(comma)pkcs11$(comma)pkcs11_tool)' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT) -run 'TestOpenSSL_Engine',integration-test-pkcs11-openssl-engine)

.PHONY: integration-test-pkcs11-provider-keygen
## integration-test-pkcs11-provider-keygen: Generate a key IN the token through `openssl genpkey`, read the public half back and sign with it
# Every other key in the suite is created by pkcs11-tool, which supplies
# CKA_CLASS and CKA_KEY_TYPE in its own template. The provider does not, so the
# module has to derive them itself -- the path where it once emitted them 4
# bytes wide, where CK_ULONG is 8, and pkcs11-provider read a garbage object
# class back and abandoned the new key.
#
# That defect is FIXED and this target is green (4/4). It keeps its own target
# because it is the only lane that exercises provider-driven keygen, which is a
# distinct path from pkcs11-tool's, not because it is expected to be red.
integration-test-pkcs11-provider-keygen:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) $(GO) test -v -tags='$(call go_tags,integration$(comma)pkcs11$(comma)pkcs11_tool)' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT) -run 'TestPKCS11ProviderKeygen',integration-test-pkcs11-provider-keygen)

.PHONY: integration-test-pkcs11-ssh-login
## integration-test-pkcs11-ssh-login: Authenticate to a real sshd with token-resident RSA, ECDSA and Ed25519 keys, every signature algorithm
# Listing a key with `ssh-keygen -D` exercises C_GetAttributeValue and nothing
# else. These complete real logins: rsa-sha2-512/rsa-sha2-256/ssh-rsa, all three
# ECDSA curves, Ed25519, and one login with no agent at all (`ssh -I`).
# authorized_keys holds exactly the key under test and both ends are pinned to
# one algorithm, so a successful login is attributable to that key and that
# mechanism.
integration-test-pkcs11-ssh-login:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) $(GO) test -v -tags='$(call go_tags,integration$(comma)pkcs11$(comma)pkcs11_tool)' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT) -run 'TestSSH_AuthenticatesWith|TestSSH_Ed25519Key',integration-test-pkcs11-ssh-login)


.PHONY: integration-test-pkcs11-openssl-all
## integration-test-pkcs11-openssl-all: Run every OpenSSL-driven PKCS#11 test (engine, provider, schemes, backend matrix)
integration-test-pkcs11-openssl-all: integration-test-pkcs11-openssl integration-test-pkcs11-openssl-provider integration-test-pkcs11-openssl-schemes integration-test-pkcs11-openssl-backends integration-test-pkcs11-openssl-engine integration-test-pkcs11-openssl-x509 integration-test-pkcs11-openssl3-provider

.PHONY: integration-test-pkcs11-openssl
## integration-test-pkcs11-openssl: Run PKCS#11 module OpenSSL integration tests (runs in devcontainer with xkms-server)
integration-test-pkcs11-openssl:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) $(GO) test -v -tags='$(call go_tags,integration$(comma)pkcs11$(comma)pkcs11_tool)' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT) -run 'TestOpenSSL',integration-test-pkcs11-openssl)

.PHONY: integration-test-pkcs11-ssh
## integration-test-pkcs11-ssh: Run PKCS#11 module SSH integration tests (runs in devcontainer with xkms-server)
integration-test-pkcs11-ssh:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) $(GO) test -v -tags='$(call go_tags,integration$(comma)pkcs11$(comma)pkcs11_tool)' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT) -run 'TestSSH',integration-test-pkcs11-ssh)

.PHONY: integration-test-pkcs11-compat-all
## integration-test-pkcs11-compat-all: Run ALL PKCS#11 compatibility tests (pkcs11-tool, OpenSSL, SSH)
integration-test-pkcs11-compat-all: integration-test-pkcs11-tool integration-test-pkcs11-openssl integration-test-pkcs11-ssh integration-test-pkcs11-ssh-login
	@echo "$(GREEN)$(BOLD)✓ All PKCS#11 compatibility tests complete!$(RESET)"

.PHONY: integration-test-pkcs11-module-all
## integration-test-pkcs11-module-all: Run EVERY PKCS#11 module test (module, external, conformance, C ABI, tool, OpenSSL, SSH)
# The single entry point for "is the PKCS#11 module we ship correct".
#
# integration-test-pkcs11-module alone is NOT that: it builds with -tags=integration,
# which excludes every file gated on pkcs11_tool or conformance -- so the external
# tool, OpenSSL and SSH compatibility suites and the whole OASIS conformance suite
# are silently skipped by it. A target that appears to cover the module while
# omitting most of its coverage is worse than no target, because a green run reads
# as proof.
#
# The list is expressed in terms of the -compat-all and -openssl-all roll-ups so
# that a lane added to either is picked up here without a second edit. Make runs
# each prerequisite at most once per invocation, so the overlap between them
# (integration-test-pkcs11-openssl is in both) costs nothing.
#
# Deliberately NOT included, because each needs something the default devcontainer
# lane does not provide and a missing dependency would read as a module defect:
#   -openssl4          needs the /usr/local/openssl-4.0.1 build (version matrix)
#   -fips              needs GOFIPS140 and re-runs conformance under it (compliance lane)
#   -module-unix/-grpc needs nothing extra but only re-runs TestMultiProtocol against
#                      another target; -module already covers those tests
#   -module-compat     a strict subset of -tool
integration-test-pkcs11-module-all: integration-test-pkcs11-module integration-test-pkcs11-module-external integration-test-pkcs11-conformance integration-test-pkcs11-cabi integration-test-pkcs11-compat-all integration-test-pkcs11-openssl-all integration-test-pkcs11-provider-keygen
	@echo "$(GREEN)$(BOLD)✓ Full PKCS#11 module suite complete!$(RESET)"

.PHONY: integration-test-pkcs11-openssl4
## integration-test-pkcs11-openssl4: Run the OpenSSL provider tests against OpenSSL 4.0.1
# OpenSSL 4.0 removed ENGINE support outright, so the provider interface is the only
# way an OpenSSL 4 application can reach a PKCS#11 module at all. The suite resolves
# the provider from the running openssl's own MODULESDIR, so pointing OPENSSL_BIN at
# the 4.0.1 build is all that is needed to re-run the same tests against it.
integration-test-pkcs11-openssl4:
	$(call run_with_server,OPENSSL_BIN=/usr/local/openssl-4.0.1/bin/openssl PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) $(GO) test -v -tags='$(call go_tags,integration$(comma)pkcs11$(comma)pkcs11_tool)' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT) -run 'TestOpenSSLProvider',integration-test-pkcs11-openssl4)

.PHONY: integration-test-pkcs11-openssl3-provider
## integration-test-pkcs11-openssl3-provider: Run the provider tests against OpenSSL 3.0.20 (the 4.0.1 build is the default lane)
# The image carries two OpenSSLs and each has its OWN pkcs11-provider build; the
# suite resolves the provider from the running openssl's MODULESDIR, so
# OPENSSL_BIN is all that has to change. The two builds are not interchangeable
# and they do NOT behave identically -- the 4.0.1 provider re-encodes EC public
# keys with explicit curve parameters while the 3.0.20 one emits a namedCurve,
# which decides whether an EC token key can act as a CA
# (TestOpenSSLProvider_ECPublicKeyExport asserts the link). Testing only one
# build would have missed that entirely.
integration-test-pkcs11-openssl3-provider:
	$(call run_with_server,OPENSSL_BIN=openssl-3 PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) $(GO) test -v -tags='$(call go_tags,integration$(comma)pkcs11$(comma)pkcs11_tool)' ./test/integration/pkcs11/module/... -timeout $(PKCS11_TEST_TIMEOUT) -run 'TestOpenSSLProvider|TestOpenSSL_TLSHandshake',integration-test-pkcs11-openssl3-provider)

.PHONY: integration-test-pkcs11-fips
## integration-test-pkcs11-fips: Run the PKCS#11 module suite in FIPS mode (approved algorithms only)
# FIPS mode changes which mechanisms the module advertises AND accepts, so it needs its
# own run: a suite that only ever exercises the default build cannot show that the
# restriction holds, nor that everything approved still works under it.
integration-test-pkcs11-fips:
	$(call run_with_server,GOFIPS140=latest PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) $(GO) test -v -tags='$(call go_tags,integration$(comma)conformance)' ./test/integration/pkcs11/module/conformance/... -timeout $(PKCS11_TEST_TIMEOUT),integration-test-pkcs11-fips)

.PHONY: integration-test-pkcs11-fips-enforcement
# The .so this lane dlopens is compiled FIPS (target-specific GOFIPS140), so it
# exercises the real FIPS build — labels and compiled crypto — not merely a
# non-FIPS build run under the GOFIPS140 environment. The harness still re-execs
# with the env; a FIPS-compiled .so agrees with it.
integration-test-pkcs11-fips-enforcement: GOFIPS140 := $(GOFIPS140_FIPS)
## integration-test-pkcs11-fips-enforcement: Run the FIPS enforcement suite (test/integration/pkcs11/module/fips)
# This package is gated `//go:build integration && fips` and NO target passed the
# fips tag, so its fifteen test functions had never been compiled into a binary,
# let alone run. They are the only tests that assert the FIPS filter end to end:
# that every mechanism C_GetMechanismList still offers under FIPS actually works,
# that the withheld ones are refused, and that CK_MECHANISM_INFO agrees with both.
# integration-test-pkcs11-fips is a different thing -- it re-runs the ordinary
# conformance suite under GOFIPS140 and never touches this package.
#
# GOFIPS140 is not set here on purpose: the harness re-executes itself with it
# (see TestMain in fips/harness_test.go), because a suite that asserted FIPS
# behaviour of a non-FIPS process would pass for the wrong reason.
integration-test-pkcs11-fips-enforcement:
	$(call run_with_server,PKCS11_MODULE=$(PKCS11_MODULE_CONTAINER) PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) PKCS11_PIN=$(PKCS11_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_AUTO_INIT_TOKEN=true XKMS_PKCS11_SO_PIN=$(PKCS11_SO_PIN) XKMS_PKCS11_USER_PIN=$(PKCS11_PIN) XKMS_PKCS11_TOKEN_LABEL=$(PKCS11_TOKEN_LABEL) XKMS_PKCS11_STORAGE_TYPE=file XKMS_PKCS11_STORAGE_PATH=/tmp/pkcs11-storage XKMS_UNIX_SOCKET=$(XKMS_UNIX_SOCKET) XKMS_GRPC_ADDR=$(XKMS_GRPC_ADDR_CONTAINER) CGO_ENABLED=1 $(GO) test -v -tags='$(call go_tags,integration$(comma)fips)' ./test/integration/pkcs11/module/fips/... -timeout $(PKCS11_TEST_TIMEOUT),integration-test-pkcs11-fips-enforcement)

.PHONY: integration-test-tpm2
## integration-test-tpm2: Run TPM2 simulator integration tests
integration-test-tpm2:
	@echo "$(CYAN)$(BOLD)→ Running TPM2 simulator integration tests...$(RESET)"
	@cd test/integration/tpm2 && $(call compose,tpm2) down -v >/dev/null 2>&1 || true
	@cd test/integration/tpm2 && $(call compose,tpm2) up -d tpm-simulator
	@echo "$(CYAN)  Waiting for TPM simulator to be ready...$(RESET)"
	@sleep 3
	@cd test/integration/tpm2 && trap '$(call compose,tpm2) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,tpm2) run --build --rm -e TPM2_SIMULATOR_HOST=tpm-simulator -e TPM2_SIMULATOR_PORT=2421 test
	@echo "$(GREEN)✓ TPM2 integration tests complete$(RESET)"

.PHONY: integration-test-peergate
## integration-test-peergate: Run the attested-caller gate suite: a go-qrdb node composed with pkg/attestation/peergate, quotes from swtpm
# The same swtpm compose as integration-test-tpm2, narrowed to the peer gate
# tests. compose run waits for the simulator's healthcheck (depends_on:
# service_healthy), so no fixed delay is needed.
integration-test-peergate:
	@echo "$(CYAN)$(BOLD)→ Running attested-caller gate integration tests (swtpm)...$(RESET)"
	@$(MAKE) --no-print-directory stage-gomodauth
	@cd test/integration/tpm2 && $(call compose,peergate) down -v >/dev/null 2>&1 || true
	@cd test/integration/tpm2 && trap '$(call compose,peergate) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,peergate) run --build --rm -e TPM2_SIMULATOR_HOST=tpm-simulator -e TPM2_SIMULATOR_PORT=2421 test \
		go test -v -count=1 -tags='$(call go_tags,integration tpm2 codec_cbor codec_json codec_msgpack gms_pure_go)' -timeout 15m \
		-run 'TestIntegration_PeerGate' ./test/integration/tpm2/...
	@echo "$(GREEN)✓ Attested-caller gate integration tests complete$(RESET)"

.PHONY: integration-test-acme-tpm
# Not in the integration-test aggregate yet: its device-attest-01 tests need
# the challenge wired (go-xkms#737, pending an owner ruling on #828). Run it
# on its own; add it to the aggregate when #737 lands.
## integration-test-acme-tpm: Run the ACME+TPM integration suite (device-attest-01, enroll-01, permanent-identifier end-to-end)
# test/integration/acme-tpm (build tags `integration tpm2`) dials swtpm
# directly AND a real ACME server (xkmsd with its embedded ACME listener
# enabled, see config.acme-tpm.yaml) -- unlike integration-test-tpm2, which
# only needs the simulator. Brings both dependency services up first so the
# `test` service's own depends_on/healthcheck conditions do not race a cold
# build; see docker-compose.yml for why the image is shared between
# acme-server and test (one Dockerfile build, two roles).
integration-test-acme-tpm:
	@echo "$(CYAN)$(BOLD)→ Running ACME+TPM integration tests...$(RESET)"
	@cd test/integration/acme-tpm && $(call compose,acme-tpm) down -v >/dev/null 2>&1 || true
	@cd test/integration/acme-tpm && $(call compose,acme-tpm) up -d --build tpm-simulator acme-server
	@echo "$(CYAN)  Waiting for swtpm and the ACME server to be ready...$(RESET)"
	@cd test/integration/acme-tpm && trap '$(call compose,acme-tpm) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,acme-tpm) run --build --rm test
	@echo "$(GREEN)✓ ACME+TPM integration tests complete$(RESET)"

.PHONY: integration-test-challenges
## integration-test-challenges: Run the ACME challenge-framework integration suite (enroll01/endorse01 availability, no TPM)
# dns01 and http01 are deliberately NOT part of this target: they are their
# own multi-service E2E stacks (docker-compose.dns01.yml /
# docker-compose.http01.yml) that still build against the pre-merge
# go-trusted-ca sibling checkout; see test/integration/challenges/docker-compose.yml.
integration-test-challenges:
	@echo "$(CYAN)$(BOLD)→ Running ACME challenge-framework integration tests...$(RESET)"
	@cd test/integration/challenges && $(call compose,challenges) down -v >/dev/null 2>&1 || true
	@cd test/integration/challenges && $(call compose,challenges) up -d --build acme-server
	@echo "$(CYAN)  Waiting for the ACME server to be ready...$(RESET)"
	@cd test/integration/challenges && trap '$(call compose,challenges) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,challenges) run --build --rm test
	@echo "$(GREEN)✓ ACME challenge-framework integration tests complete$(RESET)"

.PHONY: test-tpm2-encryption
## test-tpm2-encryption: Run TPM2 session encryption verification tests with packet capture
test-tpm2-encryption:
	@echo "$(CYAN)$(BOLD)→ Running TPM2 session encryption verification tests...$(RESET)"
	@cd test/integration/tpm2 && $(call compose,tpm2) down -v >/dev/null 2>&1 || true
	@cd test/integration/tpm2 && $(call compose,tpm2) up -d tpm-simulator
	@echo "$(CYAN)  Waiting for TPM simulator to be ready...$(RESET)"
	@sleep 3
	@cd test/integration/tpm2 && trap '$(call compose,tpm2) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,tpm2) run --rm -e TPM2_SIMULATOR_HOST=tpm-simulator -e TPM2_SIMULATOR_PORT=2421 test sh /app/test/integration/tpm2/run_capture_tests.sh
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
	@go test -v -tags='$(call go_tags,integration codec_cbor codec_json codec_msgpack)' -run 'TestTPMSession' -timeout 30m ./test/integration/tpm2/
	@echo "$(GREEN)✓ TPM2 encryption tests complete$(RESET)"

.PHONY: integration-test-awskms
## integration-test-awskms: Run AWS KMS/Floci integration tests
integration-test-awskms:
	@echo "$(CYAN)$(BOLD)→ Running AWS KMS/Floci integration tests...$(RESET)"
	@cd test/integration/awskms && $(call compose,awskms) down -v >/dev/null 2>&1 || true
	@cd test/integration/awskms && $(call compose,awskms) up -d floci
	@cd test/integration/awskms && trap '$(call compose,awskms) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,awskms) run --build --rm test
	@echo "$(GREEN)✓ AWS KMS integration tests complete$(RESET)"

.PHONY: integration-test-gcpkms
## integration-test-gcpkms: Run GCP KMS integration tests (Floci emulator + mock client)
integration-test-gcpkms:
	@echo "$(CYAN)$(BOLD)→ Running GCP KMS integration tests (Floci emulator + mock client)...$(RESET)"
	@cd test/integration/gcpkms && $(call compose,gcpkms) down -v >/dev/null 2>&1 || true
	@cd test/integration/gcpkms && trap '$(call compose,gcpkms) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,gcpkms) run --build --rm test
	@echo "$(GREEN)✓ GCP KMS integration tests complete$(RESET)"

.PHONY: integration-test-azurekv
## integration-test-azurekv: Run Azure Key Vault integration tests with mock client
integration-test-azurekv:
	@echo "$(CYAN)$(BOLD)→ Running Azure Key Vault integration tests...$(RESET)"
	@cd test/integration/azurekv && $(call compose,azurekv) down -v >/dev/null 2>&1 || true
	@cd test/integration/azurekv && trap '$(call compose,azurekv) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,azurekv) run --build --rm test
	@echo "$(GREEN)✓ Azure Key Vault integration tests complete$(RESET)"

.PHONY: integration-test-vault
## integration-test-vault: Run HashiCorp Vault integration tests
integration-test-vault:
	@echo "$(CYAN)$(BOLD)→ Running HashiCorp Vault integration tests...$(RESET)"
	@cd test/integration/vault && $(call compose,vault) down -v >/dev/null 2>&1 || true
	@cd test/integration/vault && $(call compose,vault) up -d vault
	@cd test/integration/vault && $(call compose,vault) build test
	@cd test/integration/vault && trap '$(call compose,vault) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,vault) run --build --rm test
	@echo "$(GREEN)✓ Vault integration tests complete$(RESET)"

.PHONY: integration-test-quantum
## integration-test-quantum: Run quantum-safe cryptography integration tests (ML-DSA, ML-KEM)
integration-test-quantum:
	@echo "$(CYAN)$(BOLD)→ Running quantum-safe cryptography integration tests...$(RESET)"
	@echo "$(YELLOW)Note: Testing ML-DSA signatures and ML-KEM key encapsulation$(RESET)"
	@cd test/integration/quantum && $(call compose,quantum) down -v >/dev/null 2>&1 || true
	@cd test/integration/quantum && $(call compose,quantum) build --no-cache quantum-test
	@cd test/integration/quantum && trap '$(call compose,quantum) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,quantum) run --rm quantum-test
	@echo "$(GREEN)✓ Quantum-safe integration tests complete$(RESET)"

.PHONY: test-frost
## test-frost: Run FROST unit tests (always enabled, frost tag in TEST_TAGS)
test-frost:
	@echo "$(CYAN)$(BOLD)→ Running FROST unit tests...$(RESET)"
	@$(GOTEST) $(TEST_FLAGS) ./pkg/keyprovider/frost/...
	@echo "$(GREEN)✓ FROST unit tests complete$(RESET)"

.PHONY: integration-test-frost
## integration-test-frost: Run FROST threshold signature integration tests
integration-test-frost:
ifeq ($(WITH_FROST),1)
	@echo "$(CYAN)$(BOLD)→ Running FROST threshold signature integration tests...$(RESET)"
	@echo "$(YELLOW)Note: Testing FROST key generation, signing rounds, and CLI commands$(RESET)"
	@cd test/integration/frost && $(call compose,frost) down -v >/dev/null 2>&1 || true
	@cd test/integration/frost && $(call compose,frost) build frost-test
	@cd test/integration/frost && trap '$(call compose,frost) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,frost) run --rm frost-test
	@echo "$(GREEN)✓ FROST integration tests complete$(RESET)"
else
	@echo "$(YELLOW)⚠ Skipping FROST integration tests (WITH_FROST=0)$(RESET)"
	@echo "$(YELLOW)  To enable, run: make integration-test-frost WITH_FROST=1$(RESET)"
endif

.PHONY: integration-test-webauthn
## integration-test-webauthn: Run the WebAuthn RP ceremony suite (alias of integration-test-webauthn-browser)
# There is one WebAuthn E2E suite: the Playwright suite under
# test/integration/webauthn-browser, which drives Chrome's CDP virtual
# authenticator against a real xkmsd Relying Party.
#
# The Go/chromedp suite this target used to run (test/integration/webauthn)
# was deleted: its virtual-authenticator tests exercised Chrome's own CDP
# domain and asserted nothing about our RP, and its E2E tests navigated to
# /webauthn/test -- a path the server does not serve -- while logging every
# failure instead of failing, so they passed whether or not the RP worked.
integration-test-webauthn: integration-test-webauthn-browser

.PHONY: integration-test-webauthn-browser
## integration-test-webauthn-browser: Drive Chrome's CDP virtual authenticator against the REAL xkmsd WebAuthn RP (in the devcontainer, which carries Node and Chromium's libraries)
integration-test-webauthn-browser:
	@echo "$(CYAN)$(BOLD)→ Chrome virtual authenticator → real RP (/api/v1/webauthn/*)$(RESET)"
	$(call run_in_devcontainer,mkdir -p $(BIN_DIR) && CGO_ENABLED=1 $(GO) build -buildvcs=false -tags='$(call go_tags,pkcs8 frost webauthn fido2 codec_cbor codec_json codec_msgpack)' -o $(BIN_DIR)/xkmsd ./cmd/xkmsd/ && cd test/integration/webauthn-browser && npm ci --no-fund --no-audit && npx playwright install chromium chromium-headless-shell && XKMSD_BIN=../../../$(BIN_DIR)/xkmsd npx playwright test,integration-test-webauthn-browser)

# Comma for use in function calls (Make escapes commas in function args)
comma := ,

# Docker compose command for devcontainer.
#
# The project name must always be set explicitly. Left to compose it derives
# from the file's directory ("build/docker/devcontainer" -> "devcontainer"), which is the
# same name go-trusted-platform's stack uses: sharing that namespace made
# `exec devcontainer` attach to the OTHER project's container and made
# `up -d xkms-server` match nothing at all. $(COMPOSE_NS) keeps that
# separation and adds the per-run namespace on top, so two CI jobs on one
# runner host no longer share this stack either.
#
# COMPOSE_PROJECT is only the name to report to the user; $(call compose,...)
# is what actually sets it on the command line.
COMPOSE_PROJECT := $(COMPOSE_NS)-devcontainer

# build/docker/devcontainer/compose.ci.yaml is layered on top in CI only
# (COMPOSE_RUN_ID != local, i.e. GITHUB_RUN_ID is set -- see COMPOSE_RUN_ID
# above). It replaces the base file's `..:/workspace:cached` bind mount with
# a named volume: the compose CLI resolves that relative bind source itself,
# but the container is actually created by the RUNNER HOST's daemon, not
# this job container's, so `..` names the wrong filesystem there and
# /workspace comes up empty (go-xkms #576). Local development always gets
# the plain base file, unmodified. Compose merges `volumes:` by container
# target path across -f files, so the overlay need only list the one mount
# that changes.
ifneq ($(COMPOSE_RUN_ID),local)
DOCKER_COMPOSE := $(call compose,devcontainer) -f build/docker/devcontainer/compose.yaml -f build/docker/devcontainer/compose.ci.yaml
else
DOCKER_COMPOSE := $(call compose,devcontainer) -f build/docker/devcontainer/compose.yaml
endif

# Devcontainer identity is a POSITIVE marker, never an ambient side effect.
#
# XKMS_DEVCONTAINER=1 is baked into the devcontainer image
# (build/docker/devcontainer/Dockerfile) and set again in its compose environment
# (build/docker/devcontainer/compose.yaml), so it is present in every shell that
# runs inside THE go-xkms devcontainer and nowhere else. These helpers used
# to test `[ -f /.dockerenv ]` (plus $DEVCONTAINER), which answers "am I in
# ANY container", not "am I the devcontainer": on a Gitea act_runner the job
# itself runs in a container, so that probe made the job container
# impersonate the devcontainer, the start-the-devcontainer branch was
# skipped, and the suite then waited on a socket probe inside a devcontainer
# that was never started (go-xkms #19, red on 39 of 40 runs).

# Populates a CI devcontainer's /workspace (the named volume from
# build/docker/devcontainer/compose.ci.yaml, not the dev bind mount) from this
# job's own checkout. The tree goes over the Docker API connection as a tar
# stream on `compose exec -T`'s stdin rather than depending on a shared
# filesystem, so it lands correctly no matter which host the daemon runs on
# (go-xkms #576). `tar` unpacks it inside the devcontainer as the container's
# own user, so the tree belongs to the user every target then runs as. It was
# `docker compose cp`, which creates every file as root: the first target
# that wrote into the tree, run_with_server's `mkdir -p build/lib`, failed
# with "Permission denied" (DS-3754). A no-op
# off CI (COMPOSE_RUN_ID = local, where the base file's bind mount already
# works) and a no-op once go.mod is already there, so the many
# run_in_devcontainer / run_with_server calls in one `make integration-test`
# cost a single `test -f` each after the first. Defined as one line (no
# embedded newlines) so it can be spliced into another recipe's
# backslash-continued shell chain with $(ci_sync_devcontainer_workspace).
ci_sync_devcontainer_workspace = if [ "$(COMPOSE_RUN_ID)" != "local" ] && ! $(DOCKER_COMPOSE) exec -T devcontainer test -f /workspace/go.mod >/dev/null 2>&1; then echo "$(CYAN)$(BOLD)→ Populating devcontainer /workspace from this job's checkout (CI)...$(RESET)"; tar -cf - . | $(DOCKER_COMPOSE) exec -T devcontainer tar -xf - --no-same-owner -C /workspace; fi

# Helper to run command in devcontainer (auto-starts if needed)
define run_in_devcontainer
	@if [ -n "$$XKMS_DEVCONTAINER" ]; then \
		$(1); \
	else \
		echo "$(CYAN)$(BOLD)→ Starting devcontainer...$(RESET)"; \
		$(MAKE) --no-print-directory stage-gomodauth; \
		$(DOCKER_COMPOSE) up -d devcontainer --wait 2>/dev/null || $(DOCKER_COMPOSE) up -d devcontainer; \
		$(ci_sync_devcontainer_workspace); \
		echo "$(CYAN)$(BOLD)→ Running in devcontainer: $(2)$(RESET)"; \
		$(DOCKER_COMPOSE) exec -T devcontainer bash -c "cd $(DEVCONTAINER_REPO) && $(1)"; \
	fi
endef

# Bring up the compose `xkms-server` service, which serves the Unix socket the
# PKCS#11 suites dial (shared with the devcontainer through the
# go-xkms_xkms-socket volume). Building that image compiles the whole tree, so
# `auto` -- the default -- only starts the service when the image already exists,
# and otherwise leaves the in-devcontainer fallback (scripts/start-test-xkmsd.sh)
# to serve the socket.
#   XKMS_COMPOSE_SERVER=1   always start it, building the image if necessary
#   XKMS_COMPOSE_SERVER=0   never start it; always use the fallback
XKMS_COMPOSE_SERVER ?= auto

define compose_up_xkms_server
	@$(MAKE) --no-print-directory stage-gomodauth
	@case "$(XKMS_COMPOSE_SERVER)" in \
		0|no|off) \
			echo "$(YELLOW)xkms-server disabled (XKMS_COMPOSE_SERVER=0); the devcontainer serves the socket.$(RESET)" ;; \
		1|yes|on) \
			echo "$(CYAN)$(BOLD)→ Starting xkms-server (compose)...$(RESET)"; \
			$(DOCKER_COMPOSE) up -d --build xkms-server; \
			$(MAKE) --no-print-directory devcontainer-server-wait ;; \
		*) \
			if docker image inspect $(XKMS_SERVER_IMAGE) >/dev/null 2>&1; then \
				echo "$(CYAN)$(BOLD)→ Starting xkms-server (compose)...$(RESET)"; \
				$(DOCKER_COMPOSE) up -d --build xkms-server || true; \
				$(MAKE) --no-print-directory devcontainer-server-wait || \
					$(DOCKER_COMPOSE) stop xkms-server >/dev/null 2>&1 || true; \
			else \
				echo "$(YELLOW)$(XKMS_SERVER_IMAGE) not built; the devcontainer serves the socket itself.$(RESET)"; \
				echo "$(YELLOW)Build it once with: make devcontainer-server-build$(RESET)"; \
			fi ;; \
	esac
endef

# Prints, from the host, why xkms-server is not serving the socket: the
# container's state, the socket from both containers, the suite's user's and
# root's connect, kernel LSM denials and the server log. It never prints the
# compose environment, which carries PINs (scripts/xkms-server-diagnostics.sh).
xkms_server_diagnostics = DOCKER_COMPOSE="$(DOCKER_COMPOSE)" bash scripts/xkms-server-diagnostics.sh $(XKMS_UNIX_SOCKET)

# Helper to run command in devcontainer with xkms-server running
# Usage: $(call run_with_server,command,description)
#
# The socket is served either by the compose `xkms-server` service or, when that
# service is unavailable, by scripts/start-test-xkmsd.sh inside the devcontainer.
# That script probes for a live listener before doing anything, and while the
# compose service runs it only waits for that service's socket: it never
# unlinks it or starts a second daemon on the shared path. When no server
# answers, the script exits non-zero after printing its diagnostics, the host
# adds the xkms-server side (xkms_server_diagnostics), and the target stops
# there instead of running the suite against a dead socket. The compose
# server's CA is then published for the suites (ensure-server-ca.sh); a
# server whose CA cannot be fetched from it, verified, stops the target too.
define run_with_server
	@if [ -z "$$XKMS_DEVCONTAINER" ]; then \
		echo "$(CYAN)$(BOLD)→ Starting devcontainer...$(RESET)"; \
		$(MAKE) --no-print-directory stage-gomodauth && \
		{ $(DOCKER_COMPOSE) up -d devcontainer --wait 2>/dev/null || $(DOCKER_COMPOSE) up -d devcontainer; } && \
		$(ci_sync_devcontainer_workspace) && \
		echo "$(CYAN)$(BOLD)→ Building PKCS#11 shared library in devcontainer...$(RESET)" && \
		$(DOCKER_COMPOSE) exec -T devcontainer bash -c "cd $(DEVCONTAINER_REPO) && mkdir -p build/lib && GOFIPS140=$(GOFIPS140) CGO_ENABLED=1 go build -buildvcs=false -tags '$(call go_tags,$(BUILD_TAGS))' -buildmode=c-shared -o build/lib/libxkms_pkcs11.so ./cmd/pkcs11-module" && \
		echo "$(GREEN)✓ PKCS#11 module built in devcontainer$(RESET)" || \
		{ echo "$(RED)✗ Could not build the PKCS#11 module; the suite would run against a stale .so$(RESET)"; exit 1; }; \
	fi
	$(call compose_up_xkms_server)
	@if [ -n "$$XKMS_DEVCONTAINER" ]; then \
		echo "$(CYAN)$(BOLD)→ Building PKCS#11 shared library...$(RESET)"; \
		mkdir -p build/lib && GOFIPS140=$(GOFIPS140) CGO_ENABLED=1 go build $(TAG_FLAGS) -buildmode=c-shared -o build/lib/libxkms_pkcs11.so ./cmd/pkcs11-module || \
			{ echo "$(RED)✗ Could not build the PKCS#11 module; the suite would run against a stale .so$(RESET)"; exit 1; }; \
		echo "$(GREEN)✓ PKCS#11 module built: build/lib/libxkms_pkcs11.so$(RESET)"; \
		echo "$(CYAN)$(BOLD)→ Ensuring an xkms server is listening...$(RESET)"; \
		bash scripts/start-test-xkmsd.sh $(XKMS_UNIX_SOCKET) || exit 1; \
		bash build/docker/devcontainer/scripts/ensure-server-ca.sh || exit 1; \
		$(1); \
	else \
		echo "$(CYAN)$(BOLD)→ Running in devcontainer: $(2)$(RESET)"; \
		$(DOCKER_COMPOSE) exec -T devcontainer bash -c "cd $(DEVCONTAINER_REPO) && \
			bash scripts/start-test-xkmsd.sh $(XKMS_UNIX_SOCKET)" || \
			{ $(xkms_server_diagnostics); exit 1; }; \
		$(DOCKER_COMPOSE) exec -T devcontainer bash -c "cd $(DEVCONTAINER_REPO) && \
			bash build/docker/devcontainer/scripts/ensure-server-ca.sh && \
			$(1)"; \
	fi
endef

.PHONY: devcontainer-module-env
## devcontainer-module-env: Show where the devcontainer's go command resolves modules from (never prints a credential)
# Redacted by construction: GIT_CONFIG_KEY_0 carries the module token, so only
# whether it is set is printed, never its value. The listing shows which
# first-party modules the module cache already holds before any go command runs.
devcontainer-module-env:
	$(call run_in_devcontainer,go env -json GOPROXY GOFLAGS GOMODCACHE GOPRIVATE GONOSUMDB; echo GIT_CONFIG_COUNT:; printenv GIT_CONFIG_COUNT; if printenv GIT_CONFIG_KEY_0 >/dev/null; then echo GIT_CONFIG_KEY_0 set: yes; else echo GIT_CONFIG_KEY_0 set: no; fi; echo cached first-party modules:; ls /go/pkg/mod/cache/download/github.com/jeremyhahn/ 2>/dev/null || echo none,devcontainer-module-env)

.PHONY: devcontainer-up
## devcontainer-up: Build and start go-xkms's own devcontainer stack (devcontainer + swtpm + softhsm)
devcontainer-up: stage-gomodauth
	@echo "$(CYAN)$(BOLD)→ Bringing up the go-xkms devcontainer stack...$(RESET)"
	$(DOCKER_COMPOSE) up -d --build devcontainer
	@echo "$(GREEN)✓ devcontainer is up (compose project $(COMPOSE_PROJECT))$(RESET)"

.PHONY: devcontainer-down
## devcontainer-down: Stop go-xkms's devcontainer stack (leaves volumes intact)
devcontainer-down:
	$(DOCKER_COMPOSE) down --remove-orphans

.PHONY: devcontainer-clean
## devcontainer-clean: Tear down go-xkms's devcontainer stack INCLUDING its volumes
# What CI runs on the way out. devcontainer-down deliberately keeps the volumes
# (they hold the go module and build caches a developer wants across restarts),
# but in CI the project name is unique per run, so those volumes are never
# reused -- keeping them just leaks a fresh set onto the runner host every run.
devcontainer-clean:
	$(DOCKER_COMPOSE) --profile quicbaas down -v --remove-orphans

.PHONY: devcontainer-shell
## devcontainer-shell: Open an interactive shell in go-xkms's devcontainer
devcontainer-shell: stage-gomodauth
	@$(DOCKER_COMPOSE) up -d devcontainer >/dev/null 2>&1 || true
	@$(DOCKER_COMPOSE) exec devcontainer bash

.PHONY: devcontainer-verify
## devcontainer-verify: Print the toolchain versions the integration suites depend on
devcontainer-verify: stage-gomodauth
	@$(DOCKER_COMPOSE) up -d devcontainer --wait >/dev/null 2>&1 || $(DOCKER_COMPOSE) up -d devcontainer
	@$(DOCKER_COMPOSE) exec -T devcontainer bash -c '\
		set -e; \
		echo "repo:        $$(ls -d $(DEVCONTAINER_REPO)/go.mod)"; \
		echo "ssh:         $$(ssh -V 2>&1)"; \
		echo "openssl:     $$(openssl version)"; \
		echo "openssl-3:   $$(openssl-3 version)"; \
		echo "go:          $$(go version)"; \
		echo "softhsm2:    $$(softhsm2-util --version)"; \
		echo "swtpm:       $$(swtpm --version | head -1)"; \
		echo "opensc:      $$(dpkg -s opensc | sed -n s/^Version:.//p)"; \
		echo "pkcs11-tool: OK ($$(pkcs11-tool --module $$PKCS11_LIBRARY -I | grep Cryptoki))"; \
		echo "providers:"; \
		PKCS11_MODULE_PATH=$$PKCS11_LIBRARY OPENSSL_CONF=/usr/local/openssl-4.0.1/ssl/openssl-pkcs11.cnf openssl list -providers'

.PHONY: devcontainer-server-build
## devcontainer-server-build: Build the compose xkms-server image (go-xkms-server:dev)
devcontainer-server-build:
	$(DOCKER_COMPOSE) build xkms-server

.PHONY: devcontainer-server-up
## devcontainer-server-up: Start the compose xkms-server service and wait for its Unix socket
# Deliberately does NOT pass --build. The image's build context is the whole
# repo, so any source edit invalidates the COPY layer and forces a full rebuild
# of the tree - tens of GB of layers and build cache. Rebuild explicitly with
# `make devcontainer-server-build` when the server binary needs to be refreshed.
devcontainer-server-up:
	$(DOCKER_COMPOSE) up -d xkms-server
	@$(MAKE) --no-print-directory devcontainer-server-wait

.PHONY: devcontainer-server-wait
## devcontainer-server-wait: Wait until the compose xkms-server serves the shared Unix socket
# Fails (non-zero) if it does not, so callers can fall back to
# scripts/start-test-xkmsd.sh rather than letting the suite die at C_Initialize
# with an opaque CKR_DEVICE_ERROR.
#
# Both conditions are checked: the xkms-server container must still be running
# AND the socket must accept a connection. Testing only for the socket FILE is
# not enough - the shared volume keeps the inode after a previous fallback
# xkmsd exits, so `test -S` reports success against a dead socket.
#
# The container is resolved with `compose ps -q`, never by a fixed name: the
# compose project is namespaced per run, so this lookup can only ever find
# THIS job's server even when another job's is running beside it.
# The probe runs INSIDE the devcontainer, so "the devcontainer is missing" and
# "the server is not ready yet" fail identically unless they are told apart.
# They were not: `exec -T devcontainer` wrote "no such service" to /dev/null
# fifteen times over thirty seconds, and the target then blamed xkms-server.
#
# That is how #19 read as "server not ready" across 39 consecutive runs while
# the server was serving perfectly well and no devcontainer had ever been
# started -- on a Gitea runner the job is itself containerised, so the old
# `[ -f /.dockerenv ]` test upstream read as "already inside the
# devcontainer" and skipped starting one. The upstream helpers now test the
# positive XKMS_DEVCONTAINER marker instead (see the comment above
# run_in_devcontainer), but this guard stays: a probe that cannot say which
# of two things failed sends everyone to the wrong component.
#
# The server boots with its passphrase barrier sealed and serves no socket
# until an operator opens it, so before probing, the devcontainer plays that
# operator through the sealed window (build/docker/devcontainer/scripts/open-server-barrier.sh).
#
# ✓ proves what the suites need: the opener returns only once the full,
# post-unseal server answers /health, and the socket probe then connects as
# exec's default user, the user run_with_server runs the suites as. The probe
# is scripts/socket-probe.sh (curl --unix-socket), never nc -U: the runner's
# AppArmor profile for nc.openbsd attaches to nc inside the devcontainer and
# refuses the socket on the shared volume, so nc failed for a socket every
# suite could reach. A failed
# opener is fatal; it used to be only a warning, so a probe that reached the
# sealed window's socket on its way out printed ✓ for a server the suite then
# could not use (DS-3769). Every failure ends with xkms_server_diagnostics.
devcontainer-server-wait:
	@echo "$(CYAN)$(BOLD)→ Waiting for xkms-server on $(XKMS_UNIX_SOCKET)...$(RESET)"
	@if [ -z "$$($(DOCKER_COMPOSE) ps -q devcontainer 2>/dev/null)" ]; then \
		echo "$(RED)$(BOLD)✗ cannot probe $(XKMS_UNIX_SOCKET): the devcontainer service is not running$(RESET)"; \
		echo "$(YELLOW)  The probe runs inside the devcontainer, so this says nothing about$(RESET)"; \
		echo "$(YELLOW)  xkms-server -- it may well be serving. See go-xkms#19.$(RESET)"; \
		exit 1; \
	fi; \
	cid=$$($(DOCKER_COMPOSE) ps -q xkms-server 2>/dev/null); \
	if [ -z "$$cid" ] || [ "$$(docker inspect -f '{{.State.Running}}' $$cid 2>/dev/null)" != "true" ]; then \
		echo "$(RED)$(BOLD)✗ xkms-server is not running$(RESET)"; \
		$(xkms_server_diagnostics); \
		exit 1; \
	fi; \
	if ! $(DOCKER_COMPOSE) exec -T devcontainer bash $(DEVCONTAINER_REPO)/build/docker/devcontainer/scripts/open-server-barrier.sh; then \
		echo "$(RED)$(BOLD)✗ could not open the xkms-server barrier, or the unsealed server never answered /health$(RESET)"; \
		$(xkms_server_diagnostics); \
		exit 1; \
	fi; \
	probe_err=""; \
	for i in $$(seq 1 15); do \
		if probe_err=$$($(DOCKER_COMPOSE) exec -T devcontainer sh $(DEVCONTAINER_REPO)/scripts/socket-probe.sh $(XKMS_UNIX_SOCKET) 2>&1); then \
			echo "$(GREEN)✓ xkms-server is serving $(XKMS_UNIX_SOCKET)$(RESET)"; exit 0; \
		fi; \
		sleep 2; \
	done; \
	echo "$(RED)$(BOLD)✗ xkms-server answers /health, but the suite's user cannot connect to $(XKMS_UNIX_SOCKET)$(RESET)"; \
	echo "$(YELLOW)last probe error: $${probe_err:-none}$(RESET)"; \
	$(xkms_server_diagnostics); \
	exit 1

.PHONY: integration-test-fido2
## integration-test-fido2: Run all FIDO2 integration tests (runs in devcontainer)
# xkmsctl is built with the same "integration,fido2" tags as the test package:
# only that build compiles in the //go:build integration && fido2 virtual-device
# seam (cmd/xkmsctl/fido2_virtual.go) the CLI-exec tests below need. The release
# binary (make build / make release-*) never carries those tags. See #807.
integration-test-fido2:
	$(call run_in_devcontainer,mkdir -p build/bin && CGO_ENABLED=0 $(GO) build -buildvcs=false -tags='$(call go_tags,integration$(comma)fido2$(comma)gms_pure_go)' -o build/bin/xkmsctl ./cmd/xkmsctl && $(GO) test -v -tags='$(call go_tags,integration$(comma)fido2)' ./test/integration/fido2/... -timeout 10m,integration-test-fido2)

.PHONY: integration-test-fido2-cli
## integration-test-fido2-cli: Run FIDO2 CLI command tests (runs in devcontainer)
integration-test-fido2-cli:
	$(call run_in_devcontainer,mkdir -p build/bin && CGO_ENABLED=0 $(GO) build -buildvcs=false -tags='$(call go_tags,integration$(comma)fido2$(comma)gms_pure_go)' -o build/bin/xkmsctl ./cmd/xkmsctl && $(GO) test -v -tags='$(call go_tags,integration$(comma)fido2)' ./test/integration/fido2/... -run 'CLI' -timeout 10m,integration-test-fido2-cli)

.PHONY: integration-test-fido2-hardware
## integration-test-fido2-hardware: Run FIDO2 ceremonies against a REAL attached authenticator (requires a physical YubiKey/CTAP2 key and a human to touch it)
integration-test-fido2-hardware:
	@echo "$(YELLOW)This lane needs a physical CTAP2 authenticator attached; touch it when prompted.$(RESET)"
	CGO_ENABLED=1 $(GO) test -v -count=1 -tags='$(call go_tags,integration fido2 yubikey_hardware)' \
		./test/integration/fido2/... -run 'HardwareYubiKey' -timeout 10m

.PHONY: integration-test-fido2-webauthn
## integration-test-fido2-webauthn: Run FIDO2 WebAuthn server integration tests (runs in devcontainer)
integration-test-fido2-webauthn:
	$(call run_in_devcontainer,mkdir -p build/bin && CGO_ENABLED=0 $(GO) build -buildvcs=false -tags='$(call go_tags,integration$(comma)fido2$(comma)gms_pure_go)' -o build/bin/xkmsctl ./cmd/xkmsctl && $(GO) test -v -tags='$(call go_tags,integration$(comma)fido2$(comma)webauthn)' ./test/integration/fido2/... -run 'WebAuthn' -timeout 10m,integration-test-fido2-webauthn)

.PHONY: integration-test-fido2-multiprotocol
## integration-test-fido2-multiprotocol: Run FIDO2 multi-protocol tests with virtual device (runs in devcontainer)
integration-test-fido2-multiprotocol:
	$(call run_in_devcontainer,$(GO) build -tags='$(call go_tags,integration$(comma)fido2)' -o build/bin/xkmsctl ./cmd/xkmsctl && FIDO2_USE_VIRTUAL=true $(GO) test -v -tags='$(call go_tags,integration$(comma)fido2)' ./test/integration/fido2/... -run 'MultiProtocol' -timeout 15m,integration-test-fido2-multiprotocol)

.PHONY: integration-test-uhid
## integration-test-uhid: Run UHID package integration tests (runs in devcontainer with /dev/uhid access)
## Note: Tests require root access to /dev/uhid, so run with sudo using full go path
integration-test-uhid:
	$(call run_in_devcontainer,cd xkey && sudo /usr/local/go/bin/go test -v -tags='$(call go_tags,integration$(comma)linux)' ./test/integration/uhid/... -timeout 5m,integration-test-uhid)

.PHONY: integration-test-xkey-fido2
## integration-test-xkey-fido2: Run xkey FIDO2 integration tests (runs in devcontainer with /dev/uhid access)
## Note: Tests require root access to /dev/uhid, so run with sudo using full go path
integration-test-xkey-fido2:
	$(call run_in_devcontainer,cd xkey && sudo /usr/local/go/bin/go test -v -tags='$(call go_tags,integration$(comma)linux)' ./test/integration/... -timeout 5m,integration-test-xkey-fido2)

.PHONY: integration-test-secretservice
## integration-test-secretservice: Run the freedesktop Secret Service daemon integration tests
## (secret-tool store/lookup/clear and git-credential-libsecret store/get/erase round trips)
## against `xkey secret-service` under a private dbus-run-session bus. Runs only in the
## devcontainer: it execs the real secret-tool and git-credential-libsecret binaries, which
## are not installed in the devcontainer image today (see docs/secret-service/engineering.md
## and go-xkms#723) -- this target reports that missing-tool failure rather than skip it.
integration-test-secretservice:
	$(call run_in_devcontainer,cd xkey && dbus-run-session -- $(GO) test -v -tags='$(call go_tags,integration$(comma)linux)' -run 'TestSecretService' ./test/integration -timeout 5m,integration-test-secretservice)

.PHONY: integration-test-xkey-webauthn
## integration-test-xkey-webauthn: Run Playwright browser tests against webauthn.io (Docker)
## Tests use Chrome CDP virtual authenticator to validate full WebAuthn registration + authentication flow
integration-test-xkey-webauthn:
	@echo "$(CYAN)$(BOLD)→ Running xkey Playwright WebAuthn integration tests...$(RESET)"
	@cd xkey/test/integration/webauthn && $(call compose,xkey-webauthn) down -v >/dev/null 2>&1 || true
	@cd xkey/test/integration/webauthn && trap '$(call compose,xkey-webauthn) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,xkey-webauthn) run --rm webauthn-test
	@echo "$(GREEN)✓ xkey Playwright WebAuthn integration tests complete$(RESET)"

.PHONY: integration-test-xkey-backends
## integration-test-xkey-backends: Run FIDO2 backend integration tests (software + TPM2 key backends)
integration-test-xkey-backends:
	$(call run_in_devcontainer,cd xkey && $(GO) test -v -tags='$(call go_tags,integration$(comma)linux)' -run 'TestWebAuthnFlow' ./test/integration -timeout 5m,integration-test-xkey-backends)

.PHONY: integration-test-xkey-oidc
## integration-test-xkey-oidc: Run OIDC integration tests with ORY Hydra (Docker)
## Tests use a real ORY Hydra OIDC server to validate provider discovery, PKCE, and token flows
integration-test-xkey-oidc:
	@echo "$(CYAN)$(BOLD)→ Running xkey OIDC integration tests...$(RESET)"
	@cd xkey/test/integration/oidc && $(call compose,xkey-oidc) down -v >/dev/null 2>&1 || true
	@cd xkey/test/integration/oidc && trap '$(call compose,xkey-oidc) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,xkey-oidc) run --rm test-runner
	@echo "$(GREEN)✓ xkey OIDC integration tests complete$(RESET)"

.PHONY: integration-test-xkey-piv
## integration-test-xkey-piv: Run PIV certificate storage integration tests
## Tests PIV certificate operations with file-based storage backend (no hardware required)
integration-test-xkey-piv:
	@echo "$(CYAN)$(BOLD)→ Running xkey PIV integration tests...$(RESET)"
	$(call run_in_devcontainer,cd xkey && $(GO) test -v -tags='$(call go_tags,integration)' ./test/integration/piv/... -timeout 5m,integration-test-xkey-piv)
	@echo "$(GREEN)✓ xkey PIV integration tests complete$(RESET)"

.PHONY: integration-test-xkey-oath
## integration-test-xkey-oath: Run OATH (TOTP/HOTP) integration tests
## Tests OTP generation and validation with RFC 4226/6238 compliance verification
integration-test-xkey-oath:
	@echo "$(CYAN)$(BOLD)→ Running xkey OATH integration tests...$(RESET)"
	$(call run_in_devcontainer,cd xkey && $(GO) test -v -tags='$(call go_tags,integration)' ./test/integration/oath/... -timeout 5m,integration-test-xkey-oath)
	@echo "$(GREEN)✓ xkey OATH integration tests complete$(RESET)"

.PHONY: integration-test-password-vault
## integration-test-password-vault: Password store and personal vault end to end (devcontainer): every
## vault factor on its real token against a real xkmsd, recovery, isolation, the xKey browser bridge
# One suite (xkey/test/integration/password) covers xkey's local store and the
# server vault. It builds xkmsd, xkmsctl, xkey and the test binary as the
# devcontainer user, then runs the test binary as root: the passkey leg opens
# /dev/uhid for xkey's virtual FIDO2 authenticator.
PASSWORD_VAULT_BIN := $(DEVCONTAINER_REPO)/build/bin
integration-test-password-vault: stage-gomodauth
	$(call run_in_devcontainer,if [ -s build/docker/devcontainer/gomodauth.env ]; then . build/docker/devcontainer/gomodauth.env; fi; mkdir -p build/bin && \
		$(GO) build -buildvcs=false -tags '$(call go_tags,codec_cbor codec_json codec_msgpack)' -o build/bin/xkmsd ./cmd/xkmsd && \
		$(GO) build -buildvcs=false -tags '$(call go_tags,codec_cbor codec_json codec_msgpack)' -o build/bin/xkmsctl ./cmd/xkmsctl && \
		cd xkey && GOWORK=off $(GO) build -buildvcs=false -tags '$(call go_tags,codec_json pkcs11)' -o ../build/bin/xkey ./cmd/xkey && \
		GOWORK=off $(GO) test -c -tags '$(call go_tags,integration passwordvault codec_json pkcs11)' -o ../build/bin/password-vault.test ./test/integration/password && \
		cd test/integration/password && sudo -E env XKMSD_BIN=$(PASSWORD_VAULT_BIN)/xkmsd XKMSCTL_BIN=$(PASSWORD_VAULT_BIN)/xkmsctl XKEY_CLI_BIN=$(PASSWORD_VAULT_BIN)/xkey \
		$(PASSWORD_VAULT_BIN)/password-vault.test -test.v -test.count=1 -test.timeout 20m,integration-test-password-vault)

.PHONY: integration-test-xkey-touch
## integration-test-xkey-touch: Run touch CLI integration tests
integration-test-xkey-touch:
	$(call run_in_devcontainer,cd xkey && $(GO) test -v -tags='$(call go_tags,integration)' ./test/integration/touch/... -timeout 5m,integration-test-xkey-touch)

.PHONY: integration-test-xkey-ssh
## integration-test-xkey-ssh: Run SSH agent and key management integration tests
## Tests standalone mode and xkmsd server modes (Unix socket, gRPC)
integration-test-xkey-ssh:
	@if [ -n "$$XKMS_DEVCONTAINER" ]; then \
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
		cd xkey && $(GO) test -v -tags='$(call go_tags,integration)' ./test/integration/ssh/... -timeout 5m; \
	else \
		echo "$(CYAN)$(BOLD)→ Starting devcontainer...$(RESET)"; \
		$(MAKE) --no-print-directory stage-gomodauth; \
		$(DOCKER_COMPOSE) up -d devcontainer 2>/dev/null || true; \
		echo "$(CYAN)$(BOLD)→ Rebuilding xkms-server...$(RESET)"; \
		$(DOCKER_COMPOSE) build xkms-server; \
		echo "$(CYAN)$(BOLD)→ Starting xkms-server...$(RESET)"; \
		$(DOCKER_COMPOSE) up -d xkms-server; \
		echo "$(CYAN)$(BOLD)→ Waiting for xkms-server...$(RESET)"; \
		sleep 5; \
		echo "$(CYAN)$(BOLD)→ Running in devcontainer: integration-test-xkey-ssh$(RESET)"; \
		$(DOCKER_COMPOSE) exec -T devcontainer bash -c "cd $(DEVCONTAINER_REPO) && for i in 1 2 3 4 5 6 7 8 9 10; do [ -S $(XKMS_UNIX_SOCKET) ] && break; echo 'Waiting for socket... ('$$i'/10)'; sleep 2; done && cd xkey && $(GO) test -v -tags='$(call go_tags,integration)' ./test/integration/ssh/... -timeout 5m"; \
	fi

.PHONY: integration-test-oidc-credentials
## integration-test-oidc-credentials: Server-side OIDC credentials end to end (devcontainer):
## a real xkmsd on every transport driven by xkey and xkmsctl, and the
## refresh lock and scheduler election over a real raft qrdb node
# The suite builds xkmsd, xkmsctl and xkey inside the devcontainer, so it
# resolves the private first-party modules through the staged gomodauth env.
integration-test-oidc-credentials: stage-gomodauth
	$(call run_in_devcontainer,if [ -s build/docker/devcontainer/gomodauth.env ]; then . build/docker/devcontainer/gomodauth.env; fi; $(GO) test -v -count=1 -tags='$(call go_tags,integration codec_cbor codec_json codec_msgpack)' ./test/integration/oidccredentials/... -timeout 20m,integration-test-oidc-credentials)

.PHONY: integration-test-xkey-ctap
## integration-test-xkey-ctap: Run FIDO2 CTAP protocol integration tests (MakeCredential, GetAssertion, etc.)
## Tests the full CTAP2 protocol through the UHID virtual device
integration-test-xkey-ctap:
	$(call run_in_devcontainer,cd xkey && sudo /usr/local/go/bin/go test -v -tags='$(call go_tags,integration$(comma)linux)' ./test/integration/fido2/... -timeout 10m,integration-test-xkey-ctap)

.PHONY: integration-test-xkey-luks
## integration-test-xkey-luks: Run LUKS encrypted storage integration tests (requires root for cryptsetup)
integration-test-xkey-luks:
	$(call run_in_devcontainer,mkdir -p build/bin && cd xkey && /usr/local/go/bin/go build -buildvcs=false -tags='$(call go_tags,$(XKEY_BUILD_TAGS))' -o ../build/bin/xkey ./cmd/xkey && sudo /usr/local/go/bin/go test -v -tags='$(call go_tags,integration$(comma)linux$(comma)codec_json)' ./test/integration/luks/... -timeout 10m,integration-test-xkey-luks)

.PHONY: integration-test-xkey
## integration-test-xkey: Run all xkey integration tests (FIDO2, CTAP, OIDC, PIV, OATH, Password, Touch, SSH, LUKS)
integration-test-xkey: integration-test-xkey-backends integration-test-xkey-ctap integration-test-xkey-piv integration-test-xkey-oath integration-test-password-vault integration-test-xkey-touch integration-test-xkey-ssh integration-test-xkey-luks
	@echo "$(GREEN)✓ All xkey integration tests complete$(RESET)"

.PHONY: coverage-uhid-integration
## coverage-uhid-integration: Generate UHID integration test coverage report
## Note: Tests require root access to /dev/uhid, so run with sudo using full go path
coverage-uhid-integration:
	@echo "$(CYAN)$(BOLD)→ Generating UHID integration coverage report...$(RESET)"
	$(call run_in_devcontainer,cd xkey && sudo /usr/local/go/bin/go test -v -tags='$(call go_tags,integration$(comma)linux)' -coverprofile=coverage-uhid-integration.out -covermode=atomic -coverpkg=github.com/jeremyhahn/go-xkms/pkg/fido2/uhid ./test/integration/uhid/... && /usr/local/go/bin/go tool cover -func=coverage-uhid-integration.out | tail -1,coverage-uhid-integration)
	@echo "$(GREEN)✓ UHID integration coverage report generated$(RESET)"

.PHONY: coverage-xkey-integration
## coverage-xkey-integration: Generate xkey integration test coverage report
## Note: Tests require root access to /dev/uhid, so run with sudo using full go path
coverage-xkey-integration:
	@echo "$(CYAN)$(BOLD)→ Generating xkey integration coverage report...$(RESET)"
	$(call run_in_devcontainer,cd xkey && sudo /usr/local/go/bin/go test -v -tags='$(call go_tags,integration$(comma)linux)' -coverprofile=coverage-xkey-integration.out -covermode=atomic -coverpkg=./cmd/xkey/...$(comma)github.com/jeremyhahn/go-xkms/pkg/fido2/uhid ./test/integration/... ./cmd/xkey/... && /usr/local/go/bin/go tool cover -func=coverage-xkey-integration.out | tail -1,coverage-xkey-integration)
	@echo "$(GREEN)✓ xkey integration coverage report generated$(RESET)"

.PHONY: coverage-fido2
## coverage-fido2: Generate FIDO2 integration test coverage report
coverage-fido2:
	@echo "$(CYAN)$(BOLD)→ Generating FIDO2 coverage report...$(RESET)"
	@$(GOTEST) -v -tags='$(call go_tags,integration$(comma)fido2$(comma)codec_cbor$(comma)codec_json$(comma)codec_msgpack)' -coverprofile=coverage-fido2.out ./test/integration/fido2/...
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
	@cd $(API_TEST_DIR) && $(call compose,api) down -v >/dev/null 2>&1 || true
	@cd $(API_TEST_DIR) && $(call compose,api) build
	@cd $(API_TEST_DIR) && trap '$(call compose,api) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,api) run --rm integration-tests
	@echo "$(GREEN)✓ CLI integration tests complete$(RESET)"

.PHONY: integration-test-cli-local
## integration-test-cli-local: Run CLI integration tests locally (runs in devcontainer)
integration-test-cli-local:
	$(call run_in_devcontainer,XKMS_FROST_PASSPHRASE=frost-integration-passphrase $(GO) test -v -tags='$(call go_tags,integration$(comma)frost)' ./test/integration/api/... -timeout 15m,integration-test-cli-local)

.PHONY: integration-test-signing
## integration-test-signing: Run signing package integration tests (runs in devcontainer)
integration-test-signing:
	$(call run_in_devcontainer,$(GO) test -v -tags=$(call go_tags,integration) ./test/integration/signing/... -timeout 5m,integration-test-signing)

.PHONY: integration-test-opaque
## integration-test-opaque: Run opaque key package integration tests (runs in devcontainer)
integration-test-opaque:
	$(call run_in_devcontainer,$(GO) test -v -tags=$(call go_tags,integration) ./test/integration/opaque/... -timeout 5m,integration-test-opaque)

.PHONY: integration-test-metrics
## integration-test-metrics: Run metrics package integration tests (runs in devcontainer)
integration-test-metrics:
	$(call run_in_devcontainer,$(GO) test -v -tags=$(call go_tags,integration) ./test/integration/metrics/... -timeout 5m,integration-test-metrics)

.PHONY: integration-test-health
## integration-test-health: Run health check package integration tests (runs in devcontainer)
integration-test-health:
	$(call run_in_devcontainer,$(GO) test -v -tags=$(call go_tags,integration) ./test/integration/health/... -timeout 5m,integration-test-health)

.PHONY: integration-test-ratelimit
## integration-test-ratelimit: Run rate limit package integration tests (runs in devcontainer)
integration-test-ratelimit:
	$(call run_in_devcontainer,$(GO) test -v -tags=$(call go_tags,integration) ./test/integration/ratelimit/... -timeout 5m,integration-test-ratelimit)

.PHONY: integration-test-crypto-rand
## integration-test-crypto-rand: Run crypto/rand package integration tests (runs in devcontainer)
integration-test-crypto-rand:
	$(call run_in_devcontainer,$(GO) test -v -tags=$(call go_tags,integration) ./test/integration/crypto/... -run '.*Rand.*' -timeout 5m,integration-test-crypto-rand)

.PHONY: integration-test-rand-hardware
## integration-test-rand-hardware: Run crypto/rand hardware integration tests (runs in devcontainer with SWTPM + SoftHSM)
integration-test-rand-hardware:
	$(call run_in_devcontainer,$(GO) test -v -tags=$(call go_tags,integration) ./test/integration/crypto/... -run 'TestRand.*Hardware.*' -timeout 5m,integration-test-rand-hardware)

.PHONY: integration-test-pkcs11-nitrokey
## integration-test-pkcs11-nitrokey: Run PKCS#11 Nitrokey HSM integration tests (requires physical Nitrokey HSM)
integration-test-pkcs11-nitrokey:
	@echo "$(CYAN)$(BOLD)→ Running PKCS#11 Nitrokey HSM integration tests...$(RESET)"
	@echo "$(YELLOW)Note: This requires a physical Nitrokey HSM device$(RESET)"
	@echo "$(YELLOW)Default PKCS#11 library: /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so$(RESET)"
	@echo "$(YELLOW)Default token label: go-xkms-test (UserPIN)$(RESET)"
	@echo "$(YELLOW)Default PIN: 648219$(RESET)"
	@$(GO) test -v -tags='$(call go_tags,integration$(comma)nitrokey$(comma)pkcs11)' ./test/integration/pkcs11/... -run 'TestNitrokeyHSM'
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
	$(call run_in_devcontainer,$(GO) test -v -tags=$(call go_tags,integration) ./test/integration/crypto/... -run '.*Wrap.*' -timeout 5m,integration-test-crypto-wrapping)

.PHONY: integration-test-clusterca
## integration-test-clusterca: Run the cluster CA join suite: a joiner enrolls its simulated TPM over ACME enroll-01 (runs in devcontainer)
# The joiner answers enroll-01 on 127.0.0.1:8080, the port the ACME server
# dials, so the suite needs that port free inside the devcontainer.
integration-test-clusterca:
	$(call run_in_devcontainer,$(GO) test -v -tags='$(call go_tags,integration tpm_simulator $(BUILD_TAGS))' ./test/integration/clusterca/... -timeout 10m,integration-test-clusterca)

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
	@$(GO) test -tags="$(call go_tags,cloud_integration awskms)" -v ./test/integration/awskms/...
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
	@$(GO) test -tags="$(call go_tags,cloud_integration gcpkms)" -v ./test/integration/gcpkms/...
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
	@$(GO) test -tags="$(call go_tags,cloud_integration azurekv)" -v ./test/integration/azurekv/...
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
	@AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1 FLOCI_ENDPOINT=http://localhost:4566 \
		$(GO) test -v -tags="$(call go_tags,integration awskms)" -coverprofile=$(COVERAGE_DIR)/awskms.out -covermode=atomic \
		./test/integration/awskms/... ./pkg/backend/awskms/... || ($(MAKE) emulator-stop && exit 1)
	@$(MAKE) emulator-stop
	@$(GO) tool cover -html=$(COVERAGE_DIR)/awskms.out -o $(COVERAGE_DIR)/awskms.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/awskms.out | grep total

.PHONY: coverage-gcpkms
## coverage-gcpkms: Generate GCP KMS coverage report (mock)
coverage-gcpkms:
	@mkdir -p $(COVERAGE_DIR)
	@$(GO) test -v -tags="$(call go_tags,integration gcpkms)" -coverprofile=$(COVERAGE_DIR)/gcpkms.out -covermode=atomic \
		./test/integration/gcpkms/... ./pkg/backend/gcpkms/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/gcpkms.out -o $(COVERAGE_DIR)/gcpkms.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/gcpkms.out | grep total

.PHONY: coverage-aesgcm
## coverage-aesgcm: Generate AES-256-GCM coverage report
# A named target because pkg/crypto/aesgcm is two path segments below pkg/ --
# GNU Make's pattern rules strip everything before the last "/" in a
# command-line goal before matching, so `coverage-%` (below) can never match
# `coverage-crypto/aesgcm` and there is no way to reach a nested package
# through it directly; every other pkg/crypto/* coverage target in this file
# is a named target for the same reason.
coverage-aesgcm:
	@mkdir -p $(COVERAGE_DIR)
	@$(GO) test -v $(TAG_FLAGS) -coverprofile=$(COVERAGE_DIR)/aesgcm.out -covermode=atomic ./pkg/crypto/aesgcm/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/aesgcm.out -o $(COVERAGE_DIR)/aesgcm.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/aesgcm.out | grep total

.PHONY: coverage-fips
## coverage-fips: Generate pkg/crypto/fips coverage report, merged across the
## default and GODEBUG=fips140=on lanes (go-xkms#706)
# DefaultKDF/DefaultLUKSKDF select their branch on crypto/fips140.Enabled(),
# runtime module STATE that is fixed for the life of the process (#219), not a
# build tag -- so a single `go test` run only ever exercises the branch
# matching whatever GODEBUG=fips140 was, or was not, set to when it started.
# This runs the package's tests twice, once under each state, and merges the
# two -coverprofile outputs by concatenating the second's body under the
# first's "mode:" header: `go tool cover` sums per-block hit counts for
# identical file:line blocks that appear more than once in one profile, so
# this is a correct merge of the two runs' coverage, not a reformat. Named
# for the same nested-path reason as coverage-aesgcm above.
coverage-fips:
	@mkdir -p $(COVERAGE_DIR)
	@$(GO) test -timeout $(UNIT_TEST_TIMEOUT) $(TAG_FLAGS) -coverprofile=$(COVERAGE_DIR)/fips.out -covermode=atomic ./pkg/crypto/fips/...
	@GODEBUG=fips140=on $(GO) test -timeout $(UNIT_TEST_TIMEOUT) $(TAG_FLAGS) -coverprofile=$(COVERAGE_DIR)/fips-fips140on.out -covermode=atomic ./pkg/crypto/fips/...
	@{ head -1 $(COVERAGE_DIR)/fips.out; tail -n +2 $(COVERAGE_DIR)/fips.out; tail -n +2 $(COVERAGE_DIR)/fips-fips140on.out; } > $(COVERAGE_DIR)/fips-merged.out
	@mv $(COVERAGE_DIR)/fips-merged.out $(COVERAGE_DIR)/fips.out
	@$(GO) tool cover -html=$(COVERAGE_DIR)/fips.out -o $(COVERAGE_DIR)/fips.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/fips.out | grep total

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

.PHONY: coverage-ecpoint
## coverage-ecpoint: Generate EC point package coverage report
coverage-ecpoint:
	@mkdir -p $(COVERAGE_DIR)
	@echo "$(CYAN)→ Generating EC point coverage report...$(RESET)"
	@$(GO) test -v -coverprofile=$(COVERAGE_DIR)/ecpoint.out -covermode=atomic ./pkg/crypto/ecpoint/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/ecpoint.out -o $(COVERAGE_DIR)/ecpoint.html
	@echo "$(GREEN)✓ EC point coverage report generated$(RESET)"
	@$(GO) tool cover -func=$(COVERAGE_DIR)/ecpoint.out | grep total

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
	@$(GO) test -tags=$(call go_tags,) -v -coverprofile=$(COVERAGE_DIR)/tpm2_import.out -covermode=atomic ./pkg/tpm2/... -run "Test.*Import|Test.*Export"
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
		$(GO) test -v -tags="$(call go_tags,integration azurekv)" -coverprofile=$(COVERAGE_DIR)/azurekv.out -covermode=atomic \
		./test/integration/azurekv/... ./pkg/backend/azurekv/... || ($(MAKE) emulator-stop && exit 1)
	@$(MAKE) emulator-stop
	@$(GO) tool cover -html=$(COVERAGE_DIR)/azurekv.out -o $(COVERAGE_DIR)/azurekv.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/azurekv.out | grep total

.PHONY: coverage-pkcs11
## coverage-pkcs11: Generate PKCS11 coverage report (requires SoftHSM)
coverage-pkcs11:
	@mkdir -p $(COVERAGE_DIR)
	@echo "Generating PKCS11 coverage report (requires SoftHSM installed)..."
	@$(GO) test -v -tags="$(call go_tags,integration pkcs11)" -coverprofile=$(COVERAGE_DIR)/pkcs11.out -covermode=atomic \
		./test/integration/pkcs11/... ./pkg/backend/pkcs11/...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/pkcs11.out -o $(COVERAGE_DIR)/pkcs11.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/pkcs11.out | grep total

.PHONY: coverage-tpm2
## coverage-tpm2: Generate TPM2 coverage report (requires TPM device or simulator)
coverage-tpm2:
	@mkdir -p $(COVERAGE_DIR)
	@echo "Generating TPM2 coverage report (requires TPM device at /dev/tpmrm0)..."
	@$(GO) test -v -tags="$(call go_tags,integration codec_cbor codec_json codec_msgpack)" -coverprofile=$(COVERAGE_DIR)/tpm2.out -covermode=atomic \
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

# Stage the Gitea module-fetch credentials as a BuildKit secret file
# (dependency-resolution.md §6): sourceable `export` lines, written 0600 into
# build/docker/devcontainer/ (gitignored AND dockerignored — the Dockerfile ends with
# `COPY . .`, so the file must never be plain build context). Written empty
# when no token is configured, so the same build resolves from the public
# proxy on hosts without Gitea access.
#
# The credentials are the GOMODAUTH_* resolution above; the recipe reads them
# from its exported environment so no value is expanded into the recipe text.
GOMODAUTH_FILE := build/docker/devcontainer/gomodauth.env
.PHONY: stage-gomodauth
stage-gomodauth:
	@umask 077; : > $(GOMODAUTH_FILE); \
	if [ "$$GOMODAUTH_GIT_CONFIG_COUNT" != 0 ]; then \
		{ \
			printf 'export GOPRIVATE=%s\n' "$$GOMODAUTH_GOPRIVATE"; \
			printf 'export GIT_CONFIG_COUNT=%s\n' "$$GOMODAUTH_GIT_CONFIG_COUNT"; \
			printf 'export GIT_CONFIG_KEY_0=%s\n' "$$GOMODAUTH_GIT_CONFIG_KEY_0"; \
			printf 'export GIT_CONFIG_VALUE_0=%s\n' "$$GOMODAUTH_GIT_CONFIG_VALUE_0"; \
		} > $(GOMODAUTH_FILE); \
	fi

.PHONY: gitea-host
## gitea-host: Print the resolved in-house Gitea host (GITEA_HOST override, build/docker/devcontainer/.env, or the origin remote; empty for a GitHub origin)
gitea-host:
	@if [ -n "$(GITEA_HOST)" ]; then echo "$(GITEA_HOST)"; else echo "$(YELLOW)(none: modules resolve publicly)$(RESET)"; fi

# The devcontainer image (build/docker/devcontainer/Dockerfile), which every CI
# stage runs in (handbook ci-standard.md §2). TOOLCHAIN_TAG hashes everything
# the toolchain stage is built from, so an unchanged tree reuses its image.
DEVCONTAINER_DIR := build/docker/devcontainer
DEVCONTAINER_COMPOSE := $(DEVCONTAINER_DIR)/compose.yaml
TOOLCHAIN_INPUTS := $(DEVCONTAINER_DIR)/Dockerfile $(DEVCONTAINER_DIR)/openssl-pkcs11.cnf \
	$(TOOL_PINS) scripts/build-softhsm.sh \
	go.mod go.sum sdk/go/go.mod sdk/go/go.sum xkey/go.mod xkey/go.sum \
	web/desktop/go.mod web/desktop/go.sum
TOOLCHAIN_TAG = $(shell cat $(TOOLCHAIN_INPUTS) | sha256sum | cut -c1-16)
TOOLCHAIN_IMAGE = go-xkms-toolchain:$(TOOLCHAIN_TAG)
IT_IMAGE ?= go-xkms-it:local
# IT_CI_IMAGE is the integration image CI names by its content (handbook
# ci-standard.md §9): the committed tree, plus any uncommitted or untracked
# change to it, which covers the Dockerfile, the pins and the build context.
# Every job of every run on one runner names the same image for the same
# tree, builds it once and reuses it; scripts/reap-stale-ci-stacks.sh removes
# it once it is old and unused. From ci-template v1.29 (ruling 220(5)) it also
# hashes APK_INDEX_SUM, the Alpine package index checksum CI reads with
# scripts/apk-index-sum.sh (`none` here: no base image has apk). Unset, as on
# a local or lane-verify build, the tag is the tree's alone.
APK_INDEX_SUM ?=
IT_CI_IMAGE = go-xkms-ci-it:$(shell { git rev-parse 'HEAD^{tree}'; git diff HEAD; \
	git ls-files -oz --exclude-standard | xargs -0r sha256sum; \
	$(if $(APK_INDEX_SUM),printf 'APK_INDEX_SUM=%s\n' '$(APK_INDEX_SUM)';) } 2>/dev/null | sha256sum | cut -c1-16)
# MODULE_ENV_FILE is the gomodauth secret's source: CI writes its own outside
# the checkout; locally it is the file stage-gomodauth writes.
MODULE_ENV_FILE ?= $(GOMODAUTH_FILE)
# GO_BUILD_PROXY is the GOPROXY of the image's go install / go mod download
# stages. CI sets it to <DEVCACHE_GOPROXY>|https://proxy.golang.org|direct when
# the runner's Athens answers (ci-template v1.29.4, v1.29.5); empty, the
# Dockerfile default applies. The build line quotes it, where an unquoted `|`
# is a shell pipe (handbook devcontainer.md §4).
GO_BUILD_PROXY ?=
GO_BUILD_PROXY_ARG = $(if $(GO_BUILD_PROXY),--build-arg "GO_BUILD_PROXY=$(GO_BUILD_PROXY)")
DEVCONTAINER_BUILD = DOCKER_BUILDKIT=1 docker buildx build --load \
	--build-arg GO_IMAGE=$(GO_IMAGE) \
	$(GO_BUILD_PROXY_ARG) \
	--secret id=gomodauth,src=$(MODULE_ENV_FILE) \
	-f $(DEVCONTAINER_DIR)/Dockerfile
REQUIRE_BUILDX = @docker buildx version >/dev/null 2>&1 || { echo "docker buildx is required to build $(DEVCONTAINER_DIR)/Dockerfile" >&2; exit 1; }

.PHONY: docker-build
## docker-build: Build the toolchain and integration images (build/docker/devcontainer/Dockerfile)
docker-build: docker-build-toolchain docker-build-it

.PHONY: docker-build-toolchain
## docker-build-toolchain: Build the toolchain image every CI stage runs in
# The tag is content-addressed, so a present image is already current. Jobs on
# one runner share its daemon and race to load the same tag; buildx refuses
# the loser with "already exists", which is success once the image is there.
docker-build-toolchain: stage-gomodauth
	$(REQUIRE_BUILDX)
	if docker image inspect $(TOOLCHAIN_IMAGE) >/dev/null 2>&1; then \
		echo "$(TOOLCHAIN_IMAGE) is present"; \
	else \
		$(DEVCONTAINER_BUILD) --target toolchain -t $(TOOLCHAIN_IMAGE) . || \
			docker image inspect $(TOOLCHAIN_IMAGE) >/dev/null 2>&1; \
	fi

.PHONY: docker-build-it
## docker-build-it: Build the hardened integration image (compose service `integration`)
# A content-addressed IT_IMAGE (`make -s it-image`) that is present is already
# current, and a lost load race is success, as for the toolchain image. Any
# other tag, go-xkms-it:local included, is rebuilt every time.
docker-build-it: stage-gomodauth
	$(REQUIRE_BUILDX)
	if [ "$(IT_IMAGE)" = "$(IT_CI_IMAGE)" ] && docker image inspect $(IT_IMAGE) >/dev/null 2>&1; then \
		echo "$(IT_IMAGE) is present"; \
	else \
		$(DEVCONTAINER_BUILD) --target integration --build-arg APK_INDEX_SUM='$(APK_INDEX_SUM)' -t $(IT_IMAGE) . || \
			{ [ "$(IT_IMAGE)" = "$(IT_CI_IMAGE)" ] && docker image inspect $(IT_IMAGE) >/dev/null 2>&1; }; \
	fi

.PHONY: it-image
## it-image: Print the content-addressed integration image tag CI builds (go-xkms-ci-it:<hash>)
it-image:
	@echo $(IT_CI_IMAGE)

.PHONY: toolchain-image
## toolchain-image: Print the toolchain image tag `make docker-build` builds
toolchain-image:
	@echo $(TOOLCHAIN_IMAGE)

.PHONY: deps-check
## deps-check: Fail when a direct dependency of the root, sdk/go or xkey module is behind its newest release
deps-check:
	@./scripts/deps-check.sh

.PHONY: docker-build-test-image
## docker-build-test-image: Build the root Dockerfile image `make docker-test` runs
docker-build-test-image: stage-gomodauth
	@echo "$(CYAN)$(BOLD)→ Building Docker image...$(RESET)"
	@DOCKER_BUILDKIT=1 docker buildx build --load \
		--secret id=gomodauth,src=$(GOMODAUTH_FILE) \
		-t $(DOCKER_INTEGRATION_IMAGE) -f Dockerfile .
	@echo "$(GREEN)✓ Docker image built: $(DOCKER_INTEGRATION_IMAGE)$(RESET)"

.PHONY: docker-build-server
## docker-build-server: Build Docker image for unified server
docker-build-server: stage-gomodauth
	@echo "$(CYAN)$(BOLD)→ Building unified server Docker image...$(RESET)"
	@DOCKER_BUILDKIT=1 docker buildx build --load \
		--secret id=gomodauth,src=$(GOMODAUTH_FILE) \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(PROJECT_NAME)-server:$(VERSION) \
		-t $(PROJECT_NAME)-server:latest \
		-f Dockerfile.server .
	@echo "$(GREEN)✓ Unified server Docker image built: $(PROJECT_NAME)-server:$(VERSION)$(RESET)"

.PHONY: docker-build-rest
## docker-build-rest: Build Docker image for REST server
docker-build-rest: stage-gomodauth
	@echo "$(CYAN)$(BOLD)→ Building REST server Docker image...$(RESET)"
	@DOCKER_BUILDKIT=1 docker buildx build --load \
		--secret id=gomodauth,src=$(GOMODAUTH_FILE) \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(PROJECT_NAME)-rest:$(VERSION) \
		-t $(PROJECT_NAME)-rest:latest \
		-f Dockerfile.rest .
	@echo "$(GREEN)✓ REST server Docker image built: $(PROJECT_NAME)-rest:$(VERSION)$(RESET)"

.PHONY: docker-build-grpc
## docker-build-grpc: Build Docker image for gRPC server
docker-build-grpc: stage-gomodauth
	@echo "$(CYAN)$(BOLD)→ Building gRPC server Docker image...$(RESET)"
	@DOCKER_BUILDKIT=1 docker buildx build --load \
		--secret id=gomodauth,src=$(GOMODAUTH_FILE) \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(PROJECT_NAME)-grpc:$(VERSION) \
		-t $(PROJECT_NAME)-grpc:latest \
		-f Dockerfile.grpc .
	@echo "$(GREEN)✓ gRPC server Docker image built: $(PROJECT_NAME)-grpc:$(VERSION)$(RESET)"

.PHONY: docker-build-quic
## docker-build-quic: Build Docker image for QUIC server
docker-build-quic: stage-gomodauth
	@echo "$(CYAN)$(BOLD)→ Building QUIC server Docker image...$(RESET)"
	@DOCKER_BUILDKIT=1 docker buildx build --load \
		--secret id=gomodauth,src=$(GOMODAUTH_FILE) \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(PROJECT_NAME)-quic:$(VERSION) \
		-t $(PROJECT_NAME)-quic:latest \
		-f Dockerfile.quic .
	@echo "$(GREEN)✓ QUIC server Docker image built: $(PROJECT_NAME)-quic:$(VERSION)$(RESET)"

.PHONY: docker-build-mcp
## docker-build-mcp: Build Docker image for MCP server
docker-build-mcp: stage-gomodauth
	@echo "$(CYAN)$(BOLD)→ Building MCP server Docker image...$(RESET)"
	@DOCKER_BUILDKIT=1 docker buildx build --load \
		--secret id=gomodauth,src=$(GOMODAUTH_FILE) \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(PROJECT_NAME)-mcp:$(VERSION) \
		-t $(PROJECT_NAME)-mcp:latest \
		-f Dockerfile.mcp .
	@echo "$(GREEN)✓ MCP server Docker image built: $(PROJECT_NAME)-mcp:$(VERSION)$(RESET)"

.PHONY: docker-build-cli
## docker-build-cli: Build Docker image for CLI
docker-build-cli: stage-gomodauth
	@echo "$(CYAN)$(BOLD)→ Building CLI Docker image...$(RESET)"
	@DOCKER_BUILDKIT=1 docker buildx build --load \
		--secret id=gomodauth,src=$(GOMODAUTH_FILE) \
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

# Runs CMD in the toolchain image as the invoking user, with the checkout
# bind-mounted (compose service `toolchain`), under the integration service's
# posture: make docker-run CMD='make lint'. It gets a bridge network, as CI's
# make build and make test do, because build-xkey-local and test-web run
# `npm ci`; DOCKER_RUN_NETWORK=none runs CMD offline. A workstation target; CI
# copies the checkout in instead (scripts/in-toolchain-image.sh).
CMD ?= make build
DOCKER_RUN_NETWORK ?= bridge
.PHONY: docker-run
## docker-run: Run CMD (default `make build`) in the toolchain image with the checkout mounted
docker-run: docker-build-toolchain
	GO_XKMS_TOOLCHAIN_TAG=$(TOOLCHAIN_TAG) GO_XKMS_UID=$$(id -u) GO_XKMS_GID=$$(id -g) \
		GO_XKMS_TOOLCHAIN_NETWORK=$(DOCKER_RUN_NETWORK) \
		docker compose -f $(DEVCONTAINER_COMPOSE) --profile toolchain -p go-xkms-tc-$(IMAGE_TAG) \
		run --rm toolchain sh -c '$(CMD)'

# devcontainer.json starts compose itself, with no Makefile run to export
# GO_IMAGE or stage the gomodauth secret, so its initializeCommand runs this
# on the host first. Compose interpolates from $(DEVCONTAINER_DIR)/.env, so the
# pin is kept there, beside the developer's GITEA_* lines, in step with
# scripts/tool-pins.sh.
DEVCONTAINER_ENV := $(DEVCONTAINER_DIR)/.env
.PHONY: devcontainer-env
## devcontainer-env: Write the GO_IMAGE pin into the devcontainer .env and stage gomodauth (devcontainer.json initializeCommand)
devcontainer-env: stage-gomodauth
	@umask 077; touch $(DEVCONTAINER_ENV); \
	{ grep -v '^GO_IMAGE=' $(DEVCONTAINER_ENV) || true; echo 'GO_IMAGE=$(GO_IMAGE)'; } > $(DEVCONTAINER_ENV).tmp && \
	mv $(DEVCONTAINER_ENV).tmp $(DEVCONTAINER_ENV)

.PHONY: docker-test
## docker-test: Start a new container and run make test
docker-test: docker-build-test-image
	@echo "$(CYAN)$(BOLD)→ Running tests in Docker container...$(RESET)"
	@docker run --rm \
		-v $(PWD):/workspace \
		$(GITEA_MODULE_ENV) \
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
	@docker rmi $(TOOLCHAIN_IMAGE) $(IT_IMAGE) 2>/dev/null || true
	@echo "$(GREEN)✓ Docker resources cleaned$(RESET)"

# ==============================================================================
# Docker Compose Targets
# ==============================================================================

.PHONY: compose-up
## compose-up: Start all services with docker-compose
compose-up:
	@echo "$(CYAN)$(BOLD)→ Starting services with docker-compose...$(RESET)"
	@$(call compose,root) up -d
	@echo "$(GREEN)✓ Services started$(RESET)"

.PHONY: compose-down
## compose-down: Stop all services with docker-compose
compose-down:
	@echo "$(CYAN)→ Stopping services with docker-compose...$(RESET)"
	@$(call compose,root) down -v
	@echo "$(GREEN)✓ Services stopped$(RESET)"

.PHONY: compose-test
## compose-test: Run unit tests using docker-compose
compose-test:
	@echo "$(CYAN)$(BOLD)→ Running unit tests with docker-compose...$(RESET)"
	@$(call compose,root) run --rm unit-test
	@echo "$(GREEN)$(BOLD)✓ Tests complete!$(RESET)"

.PHONY: compose-integration
## compose-integration: Run integration tests using docker-compose
compose-integration:
	@echo "$(CYAN)$(BOLD)→ Running integration tests with docker-compose...$(RESET)"
	@$(call compose,root) run --rm integration-test
	@echo "$(GREEN)$(BOLD)✓ Integration tests complete!$(RESET)"

.PHONY: compose-dev
## compose-dev: Start interactive development shell with docker-compose
compose-dev:
	@$(call compose,root) run --rm dev

.PHONY: compose-build
## compose-build: Build docker-compose images
compose-build:
	@echo "$(CYAN)$(BOLD)→ Building docker-compose images...$(RESET)"
	@$(call compose,root) build
	@echo "$(GREEN)✓ Images built$(RESET)"

.PHONY: compose-build-swtpm
## compose-build-swtpm: Build SWTPM Docker image only
compose-build-swtpm:
	@echo "$(CYAN)$(BOLD)→ Building SWTPM image...$(RESET)"
	@$(call compose,root) build swtpm
	@echo "$(GREEN)✓ SWTPM image built$(RESET)"

.PHONY: compose-build-softhsm
## compose-build-softhsm: Build SoftHSM Docker image only
compose-build-softhsm:
	@echo "$(CYAN)$(BOLD)→ Building SoftHSM image...$(RESET)"
	@$(call compose,root) build softhsm
	@echo "$(GREEN)✓ SoftHSM image built$(RESET)"

.PHONY: compose-test-integration
## compose-test-integration: Run integration tests with test-specific config
compose-test-integration:
	@echo "$(CYAN)$(BOLD)→ Running integration tests with test configuration...$(RESET)"
	@$(call compose,root) -f docker-compose.yml -f test/docker/docker-compose.test.yml up --abort-on-container-exit
	@echo "$(GREEN)$(BOLD)✓ Integration tests complete!$(RESET)"

.PHONY: compose-logs
## compose-logs: View logs from all services
compose-logs:
	@$(call compose,root) logs -f

.PHONY: compose-logs-swtpm
## compose-logs-swtpm: View SWTPM logs
compose-logs-swtpm:
	@$(call compose,root) logs -f swtpm

.PHONY: compose-logs-softhsm
## compose-logs-softhsm: View SoftHSM logs
compose-logs-softhsm:
	@$(call compose,root) logs -f softhsm

.PHONY: compose-ps
## compose-ps: Show status of all services
compose-ps:
	@$(call compose,root) ps

.PHONY: compose-clean
## compose-clean: Tear down this run's root compose stack (containers, networks, volumes)
# Deliberately NOT `--rmi all`. Container, network and volume names are
# namespaced per run, so removing them touches nothing outside this run --
# but the IMAGE TAGS (go-xkms-swtpm:latest, go-xkms-test:latest, ...) are
# shared by every run on the host by design, and deleting them forces a full
# rebuild on any job that was about to use them. Disk is reclaimed by pruning
# dangling images and build cache instead (test/scripts/clean-test-containers.sh).
compose-clean:
	@echo "$(CYAN)→ Cleaning docker-compose resources...$(RESET)"
	@$(call compose,root) down -v --remove-orphans
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

.PHONY: agsim
## agsim: Build the trusted-firmware host simulators the DICE end-to-end test enrolls (go-xkms#737)
## The pkg/acme/client device-attest-01 test runs the real firmware, compiled for
## the host, through the ACME server. The source is the trusted-firmware module at
## the version go.mod pins; the binaries land in TFWSIM_DIR, which the test's
## launcher (sdk/go/tfwsim) reads. A missing binary FAILS that test, never skips.
agsim:
	@bash scripts/build-agsim.sh "$(TFWSIM_DIR)"

.PHONY: check-insecure-tls
## check-insecure-tls: Enforce insecure-TLS/transport allowlist (fails on unapproved use)
check-insecure-tls:
	@echo "$(CYAN)$(BOLD)→ Checking insecure TLS/transport allowlist...$(RESET)"
	@bash scripts/check-insecure-tls.sh

.PHONY: check-public-literals
## check-public-literals: Public-release readiness gate -- no lab/fleet/owner literals (go-xkms#1030)
check-public-literals:
	@echo "$(CYAN)$(BOLD)→ Checking for internal literals (lab/fleet/owner)...$(RESET)"
	@bash scripts/check-public-literals.sh

# GOFLAGS takes one comma-separated -tags value.
EMPTY :=
SPACE := $(EMPTY) $(EMPTY)
COMMA := ,
BUILD_TAGS_CSV = $(subst $(SPACE),$(COMMA),$(strip $(BUILD_TAGS)))

.PHONY: check-test-helpers
## check-test-helpers: Fail if a production package imports a test-only helper (go list -deps, all modules, default and feature tags)
check-test-helpers:
	@echo "$(CYAN)$(BOLD)→ Checking that production code imports no test-only helper...$(RESET)"
	@bash scripts/check-test-helpers.sh
	@GOFLAGS=-tags=$(call go_tags,$(BUILD_TAGS_CSV)) bash scripts/check-test-helpers.sh
	@echo "$(GREEN)✓ No production package imports a test-only helper$(RESET)"


# Modules that `vet` and `lint` cover. Go tooling does not cross module
# boundaries, so `./...` from the root reaches the root module ONLY -- this
# repository has four go.mod files and CI was linting one of them (#81).
#
# gofmt is not listed here because it is path-based rather than module-based:
# `gofmt -l .` from the root already reaches every file in every module.
LINT_MODULES := . sdk/go xkey web/desktop

# Build tags per module. A linter only analyses packages the tags select, so a
# module linted without its tags reports a confident total having skipped the
# code behind them -- xkey shows 69 findings untagged and 82 tagged, and the
# root module shows 0 findings untagged against 107 under TEST_TAGS (#682):
# every *_simulator_test.go finding, including the deprecated ecdsa.PublicKey
# X/Y and elliptic.Curve.IsOnCurve accesses CI never saw, lives behind
# tpm_simulator and was invisible to a lint run that never passed that tag.
#
# It matters in the other direction too: `unused` needs the tagged code
# COMPILED to see the call sites, so linting a module untagged reports
# helpers as unused that are used perfectly well behind a tag.
#
# Each module is linted under exactly the tags its OWN tests build with --
# `make lint`/`make vet` are a coverage promise for `make test`, not a
# separate declaration that can drift from it:
#   - root and sdk/go build their tests under TEST_TAGS (test-sdk-go runs
#     `go test $(TEST_FLAGS) ./...`, and TEST_FLAGS carries TEST_TAGS), so
#     both lint under LINT_TAGS_root, TEST_TAGS comma-joined for
#     golangci-lint/go vet's -tags flag.
#   - xkey's LINT_TAGS_xkey is the widest set that compiles together, checked
#     rather than assumed: the transport/hardware tags plus every production
#     backend -- tpm2 and the awskms/azurekv/gcpkms/vault implementations,
#     which would otherwise sit outside both vet and lint entirely. All ten
#     build, vet and lint together, so no tag matrix is needed here; if two
#     ever become mutually exclusive this has to become one.
#   - web/desktop has no test target (it needs cgo + WebKit headers `make
#     vet`/`make lint` do not carry), so it stays untagged.
empty :=
space := $(empty) $(empty)
LINT_TAGS_root := $(subst $(space),$(comma),$(strip $(TEST_TAGS)))
LINT_TAGS_xkey := ble,pkcs11,usb,codec_json,tpm_simulator,tpm2,awskms,azurekv,gcpkms,vault

# Root-module tag combinations `vet`/`lint` never reached before go-xkms#1348:
# LINT_TAGS_root only ever carried TEST_TAGS, so every file behind the
# pkcs11/awskms/azurekv/gcpkms/vault hardware-and-cloud-KMS backend tags, and
# every file behind raft, was invisible to both go vet and golangci-lint --
# the same "a tag nobody passes is a directory the toolchain never opens"
# gap #650/#682 already closed for test/integration and for xkey. Two more
# passes over root close it here, each matching a tag combination CI already
# proves compiles rather than a new one invented for lint:
#   - LINT_TAGS_root_backends is LINT_TAGS_root plus pkcs8, tpm2 and the five
#     KMS backend tags -- the union of the ci.yml "build" job's matrix
#     (`pkcs8,tpm2,awskms,gcpkms,azurekv,pkcs11,vault,frost`, `go build
#     ./cmd/...`) and `make race` / the ci.yml "race" job
#     (`pkcs8,awskms,gcpkms,azurekv,pkcs11,vault,codec_cbor,codec_json,
#     codec_msgpack,frost`, `go test -race ./...`). Verified locally with
#     both `go build` and `go vet` under the exact union below (go-xkms#1348)
#     -- these tags gate disjoint files with no negated counterpart among
#     them (unlike raft, see below), so there is nothing for the union to
#     conflict on.
#   - LINT_TAGS_root_raft is LINT_TAGS_root plus raft, not the build-raft
#     job's narrower `raft codec_json` leg. raft is a boolean swap
#     (pkg/embeddednode/node_cluster.go is `//go:build raft`, node_standalone.go
#     its `//go:build !raft` counterpart), so linting it under just
#     `raft,codec_json` (matching build-raft exactly) compiles clean but
#     reports five spurious `unused` findings: helpers in
#     pkg/acme/challenges/device-attest-01/tpm_test.go and
#     pkg/tpm2/tpm.go's intelEKURL are called only from
#     `tpm_simulator`-tagged test files, so a pass without tpm_simulator
#     (which build-raft's own leg also lacks) sees the declaration but not
#     the call site and reports it dead -- an artifact of the lint tag set,
#     not a real defect. Verified locally (go-xkms#1348): `go build`/`go
#     vet` both pass under the union below, and it is the set that leaves
#     the module's `unused` results unchanged from the default pass.
LINT_TAGS_root_backends := $(LINT_TAGS_root),pkcs8,tpm2,awskms,gcpkms,azurekv,pkcs11,vault
LINT_TAGS_root_raft := $(LINT_TAGS_root),raft

# LINT_CI=1 is set by the CI Lint job only (go-xkms#1553); `make lint` for a
# developer is unchanged. The job runs in a container whose writable layer
# holds GOMODCACHE, GOCACHE and golangci-lint's analysis cache, and the six
# passes below wrote 15-16 GB into it. With LINT_CI set, every pass is
# followed by .github/scripts/disk-usage.sh, and golangci-lint's cache is
# cleaned before any pass whose tag set differs from the previous pass's:
# that cache is keyed by build tags, so a different tag set reuses none of
# it, while root -> sdk/go (same tags, sdk/go replaces root with ../..) does.
# GOCACHE is NOT cleaned: golangci-lint loads every dependency from the
# export data `make vet` already compiled under the same tags, so cleaning it
# would recompile the whole graph once more.
LINT_CI ?=

vet_empty :=
vet_space := $(vet_empty) $(vet_empty)
vet_comma := ,
# BUILD_TAGS (codecs plus the go-objstore backends: awss3, minio, gcpstorage,
# azureblob, glacier, azurearchive) as a comma list. go vet takes one -tags
# flag and keeps only the last one, so the root passes below pass a single
# -tags that is the lint tag set unioned with these; appending a second -tags
# to $(GOVET) used to silently drop BUILD_TAGS (#1348).
VET_BUILD_TAGS := $(subst $(vet_space),$(vet_comma),$(strip $(BUILD_TAGS)))

.PHONY: vet
## vet: Run go vet across every module (LINT_MODULES), plus the root module's backend and raft tag sets
vet:
	@echo "$(CYAN)$(BOLD)→ Running go vet...$(RESET)"
	@for m in $(LINT_MODULES); do \
		case "$$m" in \
			xkey) tags="$(call go_tags,$(LINT_TAGS_xkey))" ;; \
			web/desktop) tags="$(call go_tags,$(VET_BUILD_TAGS))" ;; \
			*) tags="$(call go_tags,$(LINT_TAGS_root)$(comma)$(VET_BUILD_TAGS))" ;; \
		esac; \
		echo "$(CYAN)  → go vet ($$m)$${tags:+ [tags: $$tags]}$(RESET)"; \
		( cd "$$m" && $(GO) vet $${tags:+-tags "$$tags"} ./... ) || exit 1; \
	done
	@for tags in "$(call go_tags,$(LINT_TAGS_root_backends)$(comma)$(VET_BUILD_TAGS))" "$(call go_tags,$(LINT_TAGS_root_raft)$(comma)$(VET_BUILD_TAGS))"; do \
		echo "$(CYAN)  → go vet (.) [tags: $$tags]$(RESET)"; \
		CGO_ENABLED=1 $(GO) vet -tags "$$tags" ./... || exit 1; \
	done
	@echo "$(GREEN)✓ Vet checks passed$(RESET)"

.PHONY: vet-integration
## vet-integration: Compile-only gate for every test/integration suite, one go vet per distinct //go:build tag combination (go-xkms#650)
vet-integration:
	@echo "$(CYAN)$(BOLD)→ Running go vet across test/integration (per build-tag combination)...$(RESET)"
	@scripts/vet-integration.sh
	@echo "$(GREEN)✓ Integration compile gate passed$(RESET)"

# actionlint validates workflow syntax, expressions, runner labels and (when
# shellcheck is installed) every run: script before CI sees them (go-xkms#1434).
# yaml parsers accept what Gitea rejects -- a duplicate key makes Gitea create
# no run at all, silently. Pinned; a missing or different version is replaced
# by the pin (ACTIONLINT_VERSION, scripts/tool-pins.sh), and a pin that cannot
# be installed fails the target.
ACTIONLINT_MODULE := github.com/rhysd/actionlint/cmd/actionlint
# actionlint takes files, not directories, and with no arguments lints whatever
# .github/workflows is nearest the caller's working directory: name the files
# and the config so the gate lints this repository from anywhere.
ACTIONLINT_CONFIG := $(CURDIR)/.github/actionlint.yaml
# Findings print path, line and message only, never the source excerpt
# (handbook ci-standard.md §5).
ACTIONLINT_FORMAT := {{range $$err := .}}{{$$err.Filepath}}:{{$$err.Line}}:{{$$err.Column}}: {{$$err.Message}} [{{$$err.Kind}}]{{println}}{{end}}
# The recipe globs this directory when it runs, not when make parses the file,
# so a workflow created after make started is still linted; none fails the gate.
ACTIONLINT_WORKFLOW_DIR := $(CURDIR)/.github/workflows

.PHONY: actionlint
## actionlint: Lint .github/workflows with actionlint at ACTIONLINT_VERSION (installs the pin when absent)
actionlint:
	@echo "$(CYAN)$(BOLD)→ Running actionlint $(ACTIONLINT_VERSION)...$(RESET)"
	@if [ ! -f "$(ACTIONLINT_CONFIG)" ]; then \
		echo "$(RED)$(BOLD)✗ actionlint config $(ACTIONLINT_CONFIG) is missing: it declares the self-hosted runner labels the workflows use$(RESET)"; \
		exit 1; \
	fi
	@set --; \
	for f in "$(ACTIONLINT_WORKFLOW_DIR)"/*.yml "$(ACTIONLINT_WORKFLOW_DIR)"/*.yaml; do \
		if [ -f "$$f" ]; then set -- "$$@" "$$f"; fi; \
	done; \
	if [ $$# -eq 0 ]; then \
		echo "$(RED)$(BOLD)✗ no workflows (*.yml, *.yaml) in $(ACTIONLINT_WORKFLOW_DIR): nothing for actionlint to lint$(RESET)"; \
		exit 1; \
	fi; \
	ACTIONLINT_BIN=$$(command -v actionlint 2>/dev/null || echo "$$(go env GOPATH)/bin/actionlint"); \
	if [ "$$($$ACTIONLINT_BIN -version 2>/dev/null | head -n 1)" != "$(ACTIONLINT_VERSION)" ]; then \
		$(MAKE) --no-print-directory install-actionlint || exit 1; \
		ACTIONLINT_BIN="$$(go env GOPATH)/bin/actionlint"; \
	fi; \
	if ! $$ACTIONLINT_BIN -config-file "$(ACTIONLINT_CONFIG)" -format '$(ACTIONLINT_FORMAT)' "$$@"; then \
		echo "$(RED)$(BOLD)✗ actionlint found problems in $(ACTIONLINT_WORKFLOW_DIR)$(RESET)"; \
		exit 1; \
	fi; \
	echo "$(GREEN)✓ Workflows pass actionlint$(RESET)"

# CROSS_CHECK_OSES are the platforms sdk/go must compile for with cgo off: a
# consumer cross-compiling its own binary for one of them builds every package
# the SDK imports (go-xkms#1466).
CROSS_CHECK_OSES := windows darwin

.PHONY: build-cross-check
## build-cross-check: Compile sdk/go/... with CGO_ENABLED=0 for every CROSS_CHECK_OSES platform
build-cross-check:
	@echo "$(CYAN)$(BOLD)→ Cross-compiling sdk/go for $(CROSS_CHECK_OSES)...$(RESET)"
	@failed=""; \
	for os in $(CROSS_CHECK_OSES); do \
		echo "$(CYAN)  → GOOS=$$os GOARCH=amd64 CGO_ENABLED=0 go build ./sdk/go/...$(RESET)"; \
		( cd sdk/go && GOOS=$$os GOARCH=amd64 CGO_ENABLED=0 $(GO) build ./... ) || failed="$$failed $$os"; \
	done; \
	if [ -n "$$failed" ]; then echo "$(RED)✗ sdk/go does not build for:$$failed$(RESET)"; exit 1; fi
	@echo "$(GREEN)✓ sdk/go builds for $(CROSS_CHECK_OSES)$(RESET)"

.PHONY: lint
## lint: Run actionlint over the workflows, then golangci-lint across every module (LINT_MODULES), plus the root module's backend and raft tag sets
lint: actionlint
	@echo "$(CYAN)$(BOLD)→ Running linters...$(RESET)"
	@GOLANGCI_LINT_BIN=$$(command -v golangci-lint 2>/dev/null || echo "$$HOME/go/bin/golangci-lint"); \
	if [ ! -x "$$GOLANGCI_LINT_BIN" ]; then \
		echo "$(RED)✗ golangci-lint is required but not installed$(RESET)"; \
		echo "$(YELLOW)  Install with: make install-tools$(RESET)"; \
		exit 1; \
	fi; \
	lint_ci_prev=""; \
	lint_ci_before() { \
		[ -n "$(LINT_CI)" ] || return 0; \
		if [ -n "$$lint_ci_prev" ] && [ "$$lint_ci_prev" != "x$$1" ]; then \
			echo "$(CYAN)  → golangci-lint cache clean (tags changed, nothing reusable)$(RESET)"; \
			$$GOLANGCI_LINT_BIN cache clean || exit 1; \
		fi; \
		lint_ci_prev="x$$1"; \
	}; \
	lint_ci_after() { \
		[ -z "$(LINT_CI)" ] || .github/scripts/disk-usage.sh "after golangci-lint $$1"; \
	}; \
	for m in $(LINT_MODULES); do \
		case "$$m" in \
			xkey) tags="$(call go_tags,$(LINT_TAGS_xkey))" ;; \
			web/desktop) tags="$(call go_tags,)" ;; \
			*) tags="$(call go_tags,$(LINT_TAGS_root))" ;; \
		esac; \
		lint_ci_before "$$tags"; \
		echo "$(CYAN)  → golangci-lint ($$m)$${tags:+ [tags: $$tags]}$(RESET)"; \
		if ! ( cd "$$m" && $$GOLANGCI_LINT_BIN run $${tags:+--build-tags "$$tags"} ); then \
			echo "$(RED)$(BOLD)✗ Linting failed in $$m$(RESET)"; \
			exit 1; \
		fi; \
		lint_ci_after "($$m)$${tags:+ [tags: $$tags]}"; \
	done; \
	for tags in "$(call go_tags,$(LINT_TAGS_root_backends))" "$(call go_tags,$(LINT_TAGS_root_raft))"; do \
		lint_ci_before "$$tags"; \
		echo "$(CYAN)  → golangci-lint (.) [tags: $$tags]$(RESET)"; \
		if ! CGO_ENABLED=1 $$GOLANGCI_LINT_BIN run --build-tags "$$tags"; then \
			echo "$(RED)$(BOLD)✗ Linting failed (.) [tags: $$tags]$(RESET)"; \
			exit 1; \
		fi; \
		lint_ci_after "(.) [tags: $$tags]"; \
	done; \
	echo "$(GREEN)✓ Linting complete ($(LINT_MODULES), plus root backend and raft tag sets)$(RESET)"

# --------------------------------------------------------------------------
# pkg/secure/analyzer sweep (go-xkms#549)
# --------------------------------------------------------------------------
#
# go-qrdb's pkg/secure/analyzer enforces three rules on sensitive-material
# handling (raw memguard imports outside pkg/secure, ssh.ParsePrivateKey, and
# sensitive-named struct fields typed string/[]byte) but enforces them only
# where its OWN make target runs -- nothing in go-qrdb reaches into this
# repository. `make secure-analyzer` builds the analyzer from the pinned
# go-qrdb dependency and sweeps it, as `go vet -vettool=...`, over every
# module in LINT_MODULES under every tag combination that module's own
# vet/lint/test targets already declare, so compliance is measured here
# rather than assumed. See pkg/secure/doc.go (go-qrdb) and go-xkms#549.
#
# The Makefile owns the module/tags declaration -- SECURE_ANALYZER_RUNGS is a
# flat "module tags module tags ..." list ("-" for no -tags flag), passed to
# scripts/secure-analyzer.sh as data rather than repeated there as a second
# copy that can drift from what `make vet`, `make lint` and `make test`
# already use. The root module gets TWO rungs, untagged (matching `make
# vet`) and under TEST_TAGS (matching what `make test` actually compiles):
# a single tag combination only answers for the files it compiles, and
# go-qrdb#429 measured a finding visible under the full tag set and invisible
# under the narrower one. sdk/go and web/desktop build untagged, matching
# `make vet`/`make lint`; xkey gets LINT_TAGS_xkey, the widest combination
# already declared for ITS vet/lint (see that variable's comment for why
# `desktop` is deliberately not a third web/desktop rung here either: it
# needs cgo + WebKit headers `make vet`/`make lint` do not carry).
#
# scripts/secure-analyzer-allowlist.txt is the exemption list -- not a
# baseline. Its own header documents the one named, reasoned exemption
# class (an upstream rule-2 narrowing) and the pre-existing rule-3 residue reported for triage rather than
# guessed at in the change that only wires the gate. An entry that stops
# matching anything fails the sweep as stale rather than aging out silently.
# LINT_TAGS_root (declared with LINT_MODULES above) is the same TEST_TAGS,
# comma-joined; reused here rather than recomputed so the two sweeps cannot
# drift apart on what "the root module's tags" means.
export SECURE_ANALYZER_RUNGS := . - . $(LINT_TAGS_root) sdk/go - xkey $(LINT_TAGS_xkey) web/desktop -
export SECURE_ANALYZER_ALLOWLIST := $(CURDIR)/scripts/secure-analyzer-allowlist.txt

.PHONY: secure-analyzer
## secure-analyzer: Run go-qrdb's pkg/secure analyzer over every module/tag combination (go-xkms#549)
secure-analyzer:
	@./scripts/secure-analyzer.sh --sweep

.PHONY: secure-analyzer-selftest
## secure-analyzer-selftest: Prove the secure-analyzer gate goes red on a planted violation and green on its clean counterpart
secure-analyzer-selftest:
	@./scripts/secure-analyzer-selftest.sh

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
		$$GOSEC_BIN$(call go_tags_flag,) -exclude=$(GOSEC_EXCLUDE) -severity medium -confidence medium \
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
		$$GOVULNCHECK_BIN$(call go_tags_flag,) ./... || { \
			echo "$(RED)✗ govulncheck found reachable vulnerabilities$(RESET)"; \
			exit 1; \
		}; \
		echo "$(GREEN)✓ Vulnerability scan complete$(RESET)"; \
	else \
		echo "$(YELLOW)⚠ govulncheck not found$(RESET)"; \
		echo "$(YELLOW)  Install with: make install-govulncheck$(RESET)"; \
		exit 1; \
	fi

.PHONY: trivy
## trivy: Run Trivy vulnerability scanner on filesystem (matches GitHub CI)
# test/ and examples/ are excluded: neither ships, and their fixtures and
# throwaway dependencies would otherwise dominate the report. data/, bin/ and
# build/ are local artifacts.
trivy:
	@echo "$(CYAN)$(BOLD)→ Running Trivy vulnerability scan...$(RESET)"
	@if command -v trivy >/dev/null 2>&1; then \
		trivy fs --scanners vuln,secret --severity CRITICAL,HIGH --exit-code 1 \
			--skip-dirs test --skip-dirs examples --skip-dirs data \
			--skip-dirs bin --skip-dirs build . && \
		echo "$(GREEN)✓ Trivy scan complete - no critical/high vulnerabilities found$(RESET)"; \
	else \
		echo "$(RED)✗ trivy is required but not installed (install with: make install-trivy)$(RESET)"; \
		exit 1; \
	fi

# Every product image this Makefile builds. devops.md §8 requires all of them
# to be scanned, not just the one CI happens to build.
TRIVY_IMAGES := $(PROJECT_NAME)-server:$(VERSION) $(PROJECT_NAME)-rest:$(VERSION) \
                $(PROJECT_NAME)-grpc:$(VERSION) $(PROJECT_NAME)-quic:$(VERSION) \
                $(PROJECT_NAME)-mcp:$(VERSION) $(PROJECT_NAME)-cli:$(VERSION)

.PHONY: trivy-image
## trivy-image: Build every product image and scan each with Trivy (CRITICAL/HIGH gate)
# Mirrors the gate in the ci.yml docker job so the same failure reproduces
# locally (devops.md §4). This previously depended on `docker`, which is not a
# target in this Makefile, and scanned $(REGISTRY)/$(IMAGE_NAME), neither of
# which is defined here -- so it could never have run.
#
# Not a prerequisite of `security`: it builds six images, which needs a Docker
# daemon and many minutes. Run it when a Dockerfile or its base changes.
trivy-image: docker-build-all
	@echo "$(CYAN)$(BOLD)→ Running Trivy vulnerability scan on Docker images...$(RESET)"
	@if command -v trivy >/dev/null 2>&1; then \
		rc=0; \
		for img in $(TRIVY_IMAGES); do \
			echo "$(CYAN)  Scanning $$img...$(RESET)"; \
			trivy image --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 --no-progress "$$img" || rc=1; \
		done; \
		if [ $$rc -ne 0 ]; then \
			echo "$(RED)✗ Trivy found CRITICAL/HIGH findings$(RESET)"; \
			exit 1; \
		fi; \
		echo "$(GREEN)✓ Trivy image scan complete$(RESET)"; \
	else \
		echo "$(RED)✗ trivy is required but not installed$(RESET)"; \
		echo "$(YELLOW)  Install with: make install-trivy$(RESET)"; \
		exit 1; \
	fi

.PHONY: modverify
## modverify: Verify module integrity against go.sum
modverify:
	@echo "$(CYAN)$(BOLD)→ Verifying module integrity...$(RESET)"
	@$(GO) mod verify

.PHONY: security
## security: Full devops.md §8 suite (gosec, govulncheck, go mod verify, trivy fs)
security: gosec vuln modverify trivy
	@echo "$(GREEN)$(BOLD)✓ All security scans passed!$(RESET)"
	@echo "$(YELLOW)Note: container images are scanned separately - run 'make trivy-image'$(RESET)"

.PHONY: check
## check: Run all code quality checks (fmt, vet, lint, gosec, vuln)
check: fmt vet lint gosec vuln
	@echo "$(GREEN)$(BOLD)✓ All quality checks passed!$(RESET)"

# ==============================================================================
# Tool Installation
# ==============================================================================

# TRIVY_VERSION (scripts/tool-pins.sh) is the version the toolchain image and
# the release Trivy image run (TRIVY_DIGEST in release.yml); bump them together.
# Built from source through the module proxy and checksum database, like
# actionlint, rather than by piping a remote install script into a shell.
TRIVY_MODULE := github.com/aquasecurity/trivy/cmd/trivy
# What `trivy --version` reports first. A source build reports "dev" unless the
# version is stamped the way trivy's own release build stamps it.
TRIVY_VERSION_LINE := Version: $(TRIVY_VERSION:v%=%)
TRIVY_LDFLAGS := -X github.com/aquasecurity/trivy/pkg/version/app.ver=$(TRIVY_VERSION:v%=%)

.PHONY: install-trivy
## install-trivy: Install Trivy vulnerability scanner at TRIVY_VERSION
install-trivy:
	@echo "$(CYAN)$(BOLD)→ Installing trivy $(TRIVY_VERSION)...$(RESET)"
	@if [ "$$(trivy --version 2>/dev/null | head -n 1)" = "$(TRIVY_VERSION_LINE)" ]; then \
		echo "$(GREEN)  ✓ trivy $(TRIVY_VERSION) already installed$(RESET)"; \
		exit 0; \
	fi; \
	go install -ldflags "$(TRIVY_LDFLAGS)" $(TRIVY_MODULE)@$(TRIVY_VERSION) || { \
		echo "$(RED)✗ could not install trivy $(TRIVY_VERSION)$(RESET)"; \
		exit 1; \
	}; \
	if [ "$$($$(go env GOPATH)/bin/trivy --version 2>/dev/null | head -n 1)" != "$(TRIVY_VERSION_LINE)" ]; then \
		echo "$(RED)✗ installed trivy does not report $(TRIVY_VERSION)$(RESET)"; \
		exit 1; \
	fi; \
	echo "$(GREEN)  ✓ trivy $(TRIVY_VERSION) installed$(RESET)"

.PHONY: install-govulncheck
## install-govulncheck: Install govulncheck vulnerability scanner
install-govulncheck:
	@echo "$(CYAN)$(BOLD)→ Installing govulncheck...$(RESET)"
	@if ! command -v govulncheck >/dev/null 2>&1; then \
		echo "$(CYAN)  Installing govulncheck vulnerability scanner...$(RESET)"; \
		go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION); \
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
		go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION); \
		echo "$(GREEN)  ✓ gosec installed$(RESET)"; \
	else \
		echo "$(GREEN)  ✓ gosec already installed$(RESET)"; \
	fi

.PHONY: install-actionlint
## install-actionlint: Install actionlint at ACTIONLINT_VERSION into GOPATH/bin
install-actionlint:
	@echo "$(CYAN)$(BOLD)→ Installing actionlint $(ACTIONLINT_VERSION)...$(RESET)"
	@go install $(ACTIONLINT_MODULE)@$(ACTIONLINT_VERSION) || { \
		echo "$(RED)✗ could not install actionlint $(ACTIONLINT_VERSION)$(RESET)"; \
		exit 1; \
	}
	@if [ "$$($$(go env GOPATH)/bin/actionlint -version | head -n 1)" != "$(ACTIONLINT_VERSION)" ]; then \
		echo "$(RED)✗ installed actionlint does not report $(ACTIONLINT_VERSION)$(RESET)"; \
		exit 1; \
	fi
	@echo "$(GREEN)  ✓ actionlint $(ACTIONLINT_VERSION) installed$(RESET)"

.PHONY: install-tools
## install-tools: Install development tools (golangci-lint, gosec, govulncheck, trivy, actionlint, etc.)
install-tools: install-gosec install-govulncheck install-trivy install-actionlint
	@echo "$(CYAN)$(BOLD)→ Installing development tools...$(RESET)"
	@echo "$(CYAN)  Installing golangci-lint $(GOLANGCI_VERSION) (same as the toolchain image)...$(RESET)"
	@go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)
	@echo "$(GREEN)  ✓ golangci-lint $(GOLANGCI_VERSION) installed$(RESET)"
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
		$(BUILDER_MODULE_ENV) \
		-w /workspace \
		$(CI_IMAGE_NAME):latest \
		bash -c "make ci-local"
	@echo "$(GREEN)$(BOLD)✓ CI pipeline complete!$(RESET)"

.PHONY: ci-local
## ci-local: Run CI pipeline locally (requires all tools installed)
ci-local: deps fmt-check vet lint security build-cli test race
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
	@$(MAKE) --no-print-directory clean-build-dir
	@rm -rf $(COVERAGE_DIR)
	@rm -f *.out *.log *.test *.prof
	@rm -f $(SHARED_LIB)
	@rm -f server cli xkms xkmsd
	@rm -f COMMIT_SUMMARY.md
	@find . -name "*.test" -type f -delete 2>/dev/null || true
	@find . -name "*.out" -type f -delete 2>/dev/null || true
	@find . -type d -name "tmp" -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)✓ Clean complete$(RESET)"

.PHONY: clean-build-dir
## clean-build-dir: Remove the generated entries under build/, keeping build/docker/
# build/docker/ is source, not output: the tracked devcontainer Dockerfiles,
# compose files and scripts, and the gitignored credentials stage-gomodauth and
# the developer's .env keep beside them. Everything else under $(BUILD_DIR) is
# generated (bin, lib, coverage, reports) and goes.
clean-build-dir:
	@if [ -d "$(BUILD_DIR)" ]; then \
		find "$(BUILD_DIR)" -mindepth 1 -maxdepth 1 ! -name docker -exec rm -rf {} +; \
	fi

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
	@echo "$(BOLD)Feature Build Variables:$(RESET)"
	@echo "  Every feature is compiled in by default; opt out with WITH_X=0:"
	@echo "  $(GREEN)WITH_PKCS8=1/0$(RESET)          PKCS#8 software keys (default: $(WITH_PKCS8))"
	@echo "  $(GREEN)WITH_TPM2=1/0$(RESET)           TPM 2.0 hardware keys (default: $(WITH_TPM2))"
	@echo "  $(GREEN)WITH_PKCS11=1/0$(RESET)         PKCS#11 HSM keys (default: $(WITH_PKCS11))"
	@echo "  $(GREEN)WITH_AWS_KMS=1/0$(RESET)        AWS KMS cloud keys (default: $(WITH_AWS_KMS))"
	@echo "  $(GREEN)WITH_GCP_KMS=1/0$(RESET)        GCP KMS cloud keys (default: $(WITH_GCP_KMS))"
	@echo "  $(GREEN)WITH_AZURE_KV=1/0$(RESET)       Azure Key Vault keys (default: $(WITH_AZURE_KV))"
	@echo "  $(GREEN)WITH_VAULT=1/0$(RESET)          HashiCorp Vault keys (default: $(WITH_VAULT))"
	@echo "  $(GREEN)WITH_FROST=1/0$(RESET)          FROST threshold signatures (default: $(WITH_FROST))"
	@echo "  $(GREEN)WITH_AWS_S3=1/0$(RESET)         S3 object storage (default: $(WITH_AWS_S3))"
	@echo "  $(GREEN)WITH_MINIO=1/0$(RESET)          MinIO object storage (default: $(WITH_MINIO))"
	@echo "  $(GREEN)WITH_GCP_STORAGE=1/0$(RESET)    GCS object storage (default: $(WITH_GCP_STORAGE))"
	@echo "  $(GREEN)WITH_AZURE_BLOB=1/0$(RESET)     Azure Blob object storage (default: $(WITH_AZURE_BLOB))"
	@echo "  $(GREEN)WITH_GLACIER=1/0$(RESET)        Glacier archive storage (default: $(WITH_GLACIER))"
	@echo "  $(GREEN)WITH_AZURE_ARCHIVE=1/0$(RESET)  Azure archive storage (default: $(WITH_AZURE_ARCHIVE))"
	@echo ""
	@echo "$(BOLD)Provider Variables (unset by default; set a whole provider at once):$(RESET)"
	@echo "  $(GREEN)WITH_AWS=1/0$(RESET)            AWS KMS, S3 and Glacier"
	@echo "  $(GREEN)WITH_GCP=1/0$(RESET)            GCP KMS and Cloud Storage"
	@echo "  $(GREEN)WITH_AZURE=1/0$(RESET)          Azure Key Vault, Blob and archive storage"
	@echo ""
	@echo "  $(CYAN)Examples:$(RESET)"
	@echo "    make build-full                               # Every feature"
	@echo "    make build-minimal                            # Every WITH_* feature at 0"
	@echo "    make build WITH_AWS=0 WITH_GCP=0 WITH_AZURE=0 # Drop the cloud providers"
	@echo "    make build WITH_PKCS11=0 WITH_TPM2=0          # Drop the hardware backends"
	@echo ""
	@echo "  $(YELLOW)Active feature tags:$(RESET) $(BUILD_TAGS)"
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

# PROTO_QRDB_DIR is the go-qrdb SDK's proto/ directory, so xkms.proto and
# the ACME admin.proto can
# import qrdb/v1/permission.proto (the qrdb.v1.permission method option the
# unified server's reflection interceptor enforces). Defaults to the SDK
# module at the version go.mod pins; override with
# PROTO_QRDB_DIR=/path/to/go-qrdb/sdk/go/proto.
PROTO_QRDB_DIR ?= $(shell GOWORK=off go list -m -f '{{.Dir}}' github.com/jeremyhahn/go-qrdb/sdk/go)/proto

.PHONY: proto
## proto: Generate Go code from protocol buffer definitions
proto:
	@echo "$(CYAN)$(BOLD)→ Generating Protocol Buffer code...$(RESET)"
	@if [ ! -f "pkg/api/grpc/proto/xkmsv1/xkms.proto" ]; then \
		echo "$(RED)✗ Proto file not found: pkg/api/grpc/proto/xkmsv1/xkms.proto$(RESET)"; \
		exit 1; \
	fi
	@if [ ! -f "$(PROTO_QRDB_DIR)/qrdb/v1/permission.proto" ]; then \
		echo "$(RED)✗ qrdb permission.proto not found under PROTO_QRDB_DIR=$(PROTO_QRDB_DIR)$(RESET)"; \
		exit 1; \
	fi
	@protoc -I/usr/include -I. -I$(PROTO_QRDB_DIR) \
		--go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		pkg/api/grpc/proto/xkmsv1/xkms.proto
	@protoc -I/usr/include -I. -I$(PROTO_QRDB_DIR) \
		--go_out=. --go_opt=module=github.com/jeremyhahn/go-xkms \
		--go-grpc_out=. --go-grpc_opt=module=github.com/jeremyhahn/go-xkms \
		api/proto/admin.proto
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
	@trap '$(API_COMPOSE) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM ; \
		$(API_COMPOSE) up --build --abort-on-container-exit --exit-code-from integration-tests
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
	@$(GO) test -v -tags='$(call go_tags,integration frost)' ./test/integration/api/... -timeout 10m
	@echo "$(GREEN)$(BOLD)✓ API tests complete!$(RESET)"

# ==============================================================================
# Protocol-Specific API Integration Tests
# All tests run in the devcontainer image and auto-cleanup on completion
# ==============================================================================

# Docker configuration for protocol integration tests
DEVCONTAINER_IMAGE := go-xkms-devcontainer:latest
API_TEST_NETWORK := xkms-api-test
API_COMPOSE := cd $(API_TEST_DIR) && $(call compose,api)

# Tear down THIS run's API stack, and nothing else.
#
# This used to `docker kill` a hardcoded list of container names. Those names
# were host-global, so a job cleaning up "its" containers also killed the
# identically named containers of every other job on the runner -- the same
# class of bug as the fixed compose project name, in the cleanup path. A
# `compose down` scoped to this run's project is both sufficient (the project
# owns exactly what this run created) and safe (it cannot name another's).
define kill_integration_containers
	@echo "$(CYAN)  Cleaning up this run's API test stack...$(RESET)"
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
integration-test-api-all: integration-test-api-kill integration-test-api-unix integration-test-api-rest integration-test-api-grpc integration-test-api-quic integration-test-api-ssh
	@echo "$(GREEN)$(BOLD)✓ All API protocol integration tests complete!$(RESET)"

.PHONY: integration-test-api-unix
## integration-test-api-unix: Run Unix socket protocol integration tests
integration-test-api-unix:
	@echo "$(CYAN)$(BOLD)→ Running Unix socket protocol integration tests...$(RESET)"
	$(call kill_integration_containers)
	@$(API_COMPOSE) build
	@trap '$(API_COMPOSE) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM ; \
		$(API_COMPOSE) run --rm integration-tests \
		sh -c "mkdir -p /app/build/bin && CGO_ENABLED=0 go build -buildvcs=false -tags='$(call go_tags,frost gms_pure_go)' -o /app/build/bin/xkmsctl ./cmd/xkmsctl && go test -v -tags='$(call go_tags,integration frost codec_cbor codec_json codec_msgpack)' ./test/integration/api/unix/... -timeout 10m"
	@echo "$(GREEN)✓ Unix socket protocol integration tests complete$(RESET)"

.PHONY: integration-test-api-rest
## integration-test-api-rest: Run REST API protocol integration tests
integration-test-api-rest:
	@echo "$(CYAN)$(BOLD)→ Running REST API protocol integration tests...$(RESET)"
	$(call kill_integration_containers)
	@$(API_COMPOSE) build
	@trap '$(API_COMPOSE) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM ; \
		$(API_COMPOSE) run --rm integration-tests \
		sh -c "mkdir -p /app/build/bin && CGO_ENABLED=0 go build -buildvcs=false -tags='$(call go_tags,frost gms_pure_go)' -o /app/build/bin/xkmsctl ./cmd/xkmsctl && go test -v -tags='$(call go_tags,integration frost codec_cbor codec_json codec_msgpack)' ./test/integration/api/rest/... -timeout 10m"
	@echo "$(GREEN)✓ REST API protocol integration tests complete$(RESET)"

.PHONY: integration-test-api-grpc
## integration-test-api-grpc: Run gRPC protocol integration tests
integration-test-api-grpc:
	@echo "$(CYAN)$(BOLD)→ Running gRPC protocol integration tests...$(RESET)"
	$(call kill_integration_containers)
	@$(API_COMPOSE) build
	@trap '$(API_COMPOSE) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM ; \
		$(API_COMPOSE) run --rm integration-tests \
		sh -c "mkdir -p /app/build/bin && CGO_ENABLED=0 go build -buildvcs=false -tags='$(call go_tags,frost gms_pure_go)' -o /app/build/bin/xkmsctl ./cmd/xkmsctl && go test -v -tags='$(call go_tags,integration frost codec_cbor codec_json codec_msgpack)' ./test/integration/api/grpc/... -timeout 10m"
	@echo "$(GREEN)✓ gRPC protocol integration tests complete$(RESET)"

.PHONY: integration-test-api-quic
## integration-test-api-quic: Run QUIC/HTTP3 protocol integration tests
integration-test-api-quic:
	@echo "$(CYAN)$(BOLD)→ Running QUIC/HTTP3 protocol integration tests...$(RESET)"
	$(call kill_integration_containers)
	@$(API_COMPOSE) build
	@trap '$(API_COMPOSE) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM ; \
		$(API_COMPOSE) run --rm integration-tests \
		sh -c "mkdir -p /app/build/bin && CGO_ENABLED=0 go build -buildvcs=false -tags='$(call go_tags,frost gms_pure_go)' -o /app/build/bin/xkmsctl ./cmd/xkmsctl && go test -v -tags='$(call go_tags,integration frost codec_cbor codec_json codec_msgpack)' ./test/integration/api/quic/... -timeout 10m"
	@echo "$(GREEN)✓ QUIC/HTTP3 protocol integration tests complete$(RESET)"

.PHONY: integration-test-api-mcp
## integration-test-api-mcp: Run MCP (Model Context Protocol) integration tests
integration-test-api-mcp:
	@echo "$(CYAN)$(BOLD)→ Running MCP protocol integration tests...$(RESET)"
	$(call kill_integration_containers)
	@$(API_COMPOSE) build
	@trap '$(API_COMPOSE) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM ; \
		$(API_COMPOSE) run --rm integration-tests \
		sh -c "mkdir -p /app/build/bin && CGO_ENABLED=0 go build -buildvcs=false -tags='$(call go_tags,frost gms_pure_go)' -o /app/build/bin/xkmsctl ./cmd/xkmsctl && go test -v -tags='$(call go_tags,integration frost codec_cbor codec_json codec_msgpack)' ./test/integration/api/... -run 'MCP|Mcp' -timeout 10m"
	@echo "$(GREEN)✓ MCP protocol integration tests complete$(RESET)"

.PHONY: integration-test-api-ssh
## integration-test-api-ssh: Run SSH multi-protocol integration tests driving the xkey CLI against xkmsd
integration-test-api-ssh:
	@echo "$(CYAN)$(BOLD)→ Running SSH multi-protocol integration tests (xkey CLI vs xkmsd)...$(RESET)"
	$(call kill_integration_containers)
	@$(API_COMPOSE) build
	@trap '$(API_COMPOSE) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM ; \
		$(API_COMPOSE) run --rm integration-tests \
		sh -c "mkdir -p /app/build/bin && CGO_ENABLED=0 go build -buildvcs=false -tags='$(call go_tags,frost gms_pure_go)' -o /app/build/bin/xkmsctl ./cmd/xkmsctl && (cd xkey && go build -tags='$(call go_tags,codec_cbor codec_json codec_msgpack)' -o /app/build/bin/xkey ./cmd/xkey) && XKMS_SSH_TEST_BACKENDS=software,tpm2,pkcs11 XKEY_CLI_BIN=/app/build/bin/xkey go test -v -tags='$(call go_tags,integration frost codec_cbor codec_json codec_msgpack)' ./test/integration/api/... -run 'XkeySSH' -timeout 10m"
	@echo "$(GREEN)✓ SSH multi-protocol integration tests complete$(RESET)"

.PHONY: integration-test-ssh-backends
## integration-test-ssh-backends: Confirm SSH key gen+sign+verify on EVERY backend (software/tpm2-sim/pkcs11-SoftHSM2/cloud); AWS via Floci, GCP+Azure via self-consistent mocks
integration-test-ssh-backends:
	@echo "$(CYAN)$(BOLD)→ Running per-backend SSH key generate/sign/verify suite...$(RESET)"
	@$(AWSKMS_COMPOSE) down -v --remove-orphans >/dev/null 2>&1 || true
	@# This suite runs on the HOST, so unlike the other lanes it needs floci's
	@# PUBLISHED port. That port is ephemeral (see the compose file) precisely
	@# so two jobs on one runner host can each have one, so ask docker which
	@# one it got rather than assuming 4566. Teardown is a trap, not a
	@# trailing command: a cancelled job is killed by signal and would
	@# otherwise leak the stack onto the host forever.
	@trap '$(AWSKMS_COMPOSE) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM ; \
		$(AWSKMS_COMPOSE) up -d --wait floci ; \
		FLOCI_ENDPOINT=$$($(AWSKMS_COMPOSE) port floci 4566 | sed 's/^0\.0\.0\.0:/127.0.0.1:/') ; \
		[ -n "$$FLOCI_ENDPOINT" ] || { echo "$(RED)✗ floci published no host port for 4566$(RESET)"; exit 1; } ; \
		AWS_ENDPOINT_URL=http://$$FLOCI_ENDPOINT AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1 \
		CGO_ENABLED=1 $(GO) test -v -tags '$(call go_tags,integration tpm_simulator pkcs11 awskms gcpkms azurekv)' \
		./test/integration/sshbackend/... -timeout 15m
	@echo "$(GREEN)✓ Per-backend SSH suite complete$(RESET)"

.PHONY: integration-test-ssh-backends-cloud-real
## integration-test-ssh-backends-cloud-real: SSH key gen+sign+verify against LIVE cloud KMS (opt-in; needs AWS_*/GCPKMS_*/AZURE_* creds; never in CI)
integration-test-ssh-backends-cloud-real:
	@echo "$(CYAN)$(BOLD)→ Running per-backend SSH suite against LIVE cloud KMS (opt-in)...$(RESET)"
	CGO_ENABLED=1 $(GO) test -v -tags '$(call go_tags,integration cloud_real awskms gcpkms azurekv)' \
		./test/integration/sshbackend/... -run TestSSHBackend_CloudReal -timeout 20m
	@echo "$(GREEN)✓ Live cloud SSH suite complete$(RESET)"

.PHONY: integration-test-api-frost
## integration-test-api-frost: Run FROST API integration tests across all protocols
integration-test-api-frost:
ifeq ($(WITH_FROST),1)
	@echo "$(CYAN)$(BOLD)→ Running FROST API integration tests...$(RESET)"
	$(call kill_integration_containers)
	@$(API_COMPOSE) build
	@trap '$(API_COMPOSE) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM ; \
		$(API_COMPOSE) run --rm integration-tests \
		sh -c "mkdir -p /app/build/bin && CGO_ENABLED=0 go build -buildvcs=false -tags='$(call go_tags,frost gms_pure_go)' -o /app/build/bin/xkmsctl ./cmd/xkmsctl && go test -v -tags='$(call go_tags,integration frost codec_cbor codec_json codec_msgpack)' ./test/integration/api/... -run 'FROST' -timeout 15m"
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
	@trap '$(API_COMPOSE) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM ; \
		$(API_COMPOSE) run --rm integration-tests \
		sh -c "mkdir -p /app/build/bin && CGO_ENABLED=0 go build -buildvcs=false -tags='$(call go_tags,frost gms_pure_go)' -o /app/build/bin/xkmsctl ./cmd/xkmsctl && go test -v -tags='$(call go_tags,integration frost codec_cbor codec_json codec_msgpack)' ./test/integration/api/... -run 'Parity|AllProtocols' -timeout 20m"
	@echo "$(GREEN)✓ API protocol parity tests complete$(RESET)"

.PHONY: integration-test-sdk-go
## integration-test-sdk-go: Run Go SDK embedded integration tests in devcontainer
integration-test-sdk-go:
	@echo "$(CYAN)$(BOLD)→ Running Go SDK embedded integration tests...$(RESET)"
	$(call run_in_devcontainer,$(GO) test -v -tags='$(call go_tags,integration codec_cbor codec_json codec_msgpack)' ./test/integration/sdk/go/... -run 'TestSDKMultiProtocol$$|TestMultiProtocolKeyOperationsConcurrent|TestMultiProtocolDataIntegrity' -timeout 15m,integration-test-sdk-go)
	@echo "$(GREEN)✓ Go SDK embedded integration tests complete$(RESET)"

.PHONY: integration-test-sshagent
## integration-test-sshagent: Run agent-only SSH session acceptance tests (real git commit -S through the agent socket)
integration-test-sshagent:
	@echo "$(CYAN)$(BOLD)→ Running agent-only SSH session integration tests...$(RESET)"
	$(call run_in_devcontainer,$(GO) test -v -tags='$(call go_tags,integration)' ./test/integration/sshagent/... -timeout 5m,integration-test-sshagent)
	@echo "$(GREEN)✓ Agent-only SSH session integration tests complete$(RESET)"

.PHONY: integration-test-initceremony
## integration-test-initceremony: xkmsd init persists admin factors across a restart (builds and runs its own xkmsd)
integration-test-initceremony:
	@echo "$(CYAN)$(BOLD)→ Running init-ceremony integration tests...$(RESET)"
	$(call run_in_devcontainer,$(GO) test -v -tags='$(call go_tags,integration initceremony codec_cbor codec_json codec_msgpack tpm_simulator)' ./test/integration/initceremony/... -timeout 10m,integration-test-initceremony)
	@echo "$(GREEN)✓ Init-ceremony integration tests complete$(RESET)"

.PHONY: integration-test-sdk-go-remote
## integration-test-sdk-go-remote: Run Go SDK remote protocol integration tests against docker-compose server
integration-test-sdk-go-remote:
	@echo "$(CYAN)$(BOLD)→ Running Go SDK remote integration tests...$(RESET)"
	$(call kill_integration_containers)
	@$(API_COMPOSE) build
	@trap '$(API_COMPOSE) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM ; \
		$(API_COMPOSE) run --rm integration-tests \
		sh -c "go test -v -tags='$(call go_tags,integration codec_cbor codec_json codec_msgpack)' ./test/integration/sdk/go/... -run 'TestSDKMultiProtocolRemote' -timeout 20m"
	@echo "$(GREEN)✓ Go SDK remote integration tests complete$(RESET)"

# ==============================================================================
# Bootstrap Integration Tests
# ==============================================================================

BOOTSTRAP_COMPOSE := $(call compose,bootstrap) -f test/integration/bootstrap/docker-compose.yml

# Absolute -f path: the ssh-backend lane tears its stack down from a trap,
# which can fire with the shell in any directory.
AWSKMS_COMPOSE := $(call compose,awskms) -f $(CURDIR)/test/integration/awskms/docker-compose.yml

.PHONY: integration-test-bootstrap
## integration-test-bootstrap: Run bootstrap integration tests (DANE/TLSA, Noise, SPKI, Direct, Auto)
integration-test-bootstrap:
	@echo "$(CYAN)$(BOLD)→ Running bootstrap integration tests...$(RESET)"
	@cd test/integration/bootstrap && $(call compose,bootstrap) down -v >/dev/null 2>&1 || true
	@cd test/integration/bootstrap && trap '$(call compose,bootstrap) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,bootstrap) run --build --rm test
	@echo "$(GREEN)✓ Bootstrap integration tests complete$(RESET)"

.PHONY: integration-test-acmeadmin
## integration-test-acmeadmin: Run ACME admin plane CLI integration tests (xkmsctl acme/xkmsctl tenant against a real xkmsd, REST only)
integration-test-acmeadmin: stage-gomodauth
	@echo "$(CYAN)$(BOLD)→ Running ACME admin plane integration tests...$(RESET)"
	@cd test/integration/acmeadmin && $(call compose,acmeadmin) down -v >/dev/null 2>&1 || true
	@cd test/integration/acmeadmin && trap '$(call compose,acmeadmin) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,acmeadmin) run --build --rm test
	@echo "$(GREEN)✓ ACME admin plane integration tests complete$(RESET)"

.PHONY: integration-test-cluster
## integration-test-cluster: Run 3-node Raft cluster + standalone-server integration tests (crypto gen/sign/verify replication, public-key consistency, delete replication, leader failover, node restart/rejoin catch-up, standalone lifecycle)
integration-test-cluster: stage-gomodauth
	@echo "$(CYAN)$(BOLD)→ Running 3-node Raft cluster + standalone-server integration tests...$(RESET)"
	@cd test/integration/cluster && bash gen-certs.sh
	@cd test/integration/cluster && $(call compose,cluster) down -v >/dev/null 2>&1 || true
	@cd test/integration/cluster && trap '$(call compose,cluster) down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,cluster) run --build --rm test
	@echo "$(GREEN)✓ Cluster integration tests complete$(RESET)"

.PHONY: integration-test-truststrap
## integration-test-truststrap: Run xkey TrustService truststrap integration tests (Direct, SPKI, Noise)
integration-test-truststrap:
	@echo "$(CYAN)$(BOLD)→ Running xkey TrustService truststrap integration tests...$(RESET)"
	@cd test/integration/bootstrap && $(call compose,bootstrap) --profile xkey down -v >/dev/null 2>&1 || true
	@cd test/integration/bootstrap && $(call compose,bootstrap) --profile xkey build xkey-truststrap-test
	@cd test/integration/bootstrap && trap '$(call compose,bootstrap) --profile xkey down -v --remove-orphans >/dev/null 2>&1' EXIT INT TERM && \
		$(call compose,bootstrap) --profile xkey run --rm xkey-truststrap-test
	@echo "$(GREEN)✓ xkey TrustService truststrap integration tests complete$(RESET)"

# ------------------------------------------------------------------
# Developer backend server (xkms-server reachable from host)
# ------------------------------------------------------------------

.PHONY: dev-server-up
## dev-server-up: Start a live xkms-server on localhost:8443 for interactive GUI testing
dev-server-up:
	@echo "$(CYAN)$(BOLD)→ Starting xkms-server dev instance...$(RESET)"
	@$(BOOTSTRAP_COMPOSE) up -d xkms-server
	@echo "$(CYAN)→ Waiting for health check...$(RESET)"
	@cid=$$($(BOOTSTRAP_COMPOSE) ps -q xkms-server); \
	for i in $$(seq 1 30); do \
		if docker inspect --format='{{.State.Health.Status}}' $$cid 2>/dev/null | grep -q healthy; then \
			break; \
		fi; \
		sleep 1; \
	done
	@CONTAINER=$$($(BOOTSTRAP_COMPOSE) ps -q xkms-server) \
		bash test/integration/bootstrap/scripts/print-dev-server-info.sh

.PHONY: dev-server-down
## dev-server-down: Stop the dev xkms-server
dev-server-down:
	@echo "$(CYAN)$(BOLD)→ Stopping xkms-server dev instance...$(RESET)"
	@$(BOOTSTRAP_COMPOSE) down -v --remove-orphans
	@rm -f /tmp/xkms-dev-ca.crt
	@echo "$(GREEN)✓ Dev server stopped$(RESET)"

.PHONY: dev-server-info
## dev-server-info: Print connection info + credentials for the running dev xkms-server
dev-server-info:
	@CONTAINER=$$($(BOOTSTRAP_COMPOSE) ps -q xkms-server) \
		bash test/integration/bootstrap/scripts/print-dev-server-info.sh

.PHONY: dev-server-logs
## dev-server-logs: Tail logs from the running dev xkms-server
dev-server-logs:
	@docker logs -f $$($(BOOTSTRAP_COMPOSE) ps -q xkms-server)

.PHONY: test-e2e-live
## test-e2e-live: Run live-backend Playwright tests (requires dev-server-up + xkey dev-browser)
test-e2e-live:
	@echo "$(CYAN)$(BOLD)→ Running live-backend Playwright tests...$(RESET)"
	@if [ -z "$$($(BOOTSTRAP_COMPOSE) ps -q xkms-server)" ]; then \
		echo "$(RED)ERROR: xkms-server not running. Run 'make dev-server-up' first.$(RESET)"; \
		exit 1; \
	fi
	@if ! curl --silent --fail http://localhost:34115/ >/dev/null 2>&1; then \
		echo "$(RED)ERROR: xkey dev server not reachable at http://localhost:34115.$(RESET)"; \
		echo "  Run 'cd xkey && make dev-browser' in a separate terminal, then rerun."; \
		exit 1; \
	fi
	@cid=$$($(BOOTSTRAP_COMPOSE) ps -q xkms-server); \
	HOST_REST_PORT=$$(docker port $$cid 8443/tcp | head -1 | awk -F: '{print $$NF}'); \
	HOST_NOISE_PORT=$$(docker port $$cid 8445/tcp | head -1 | awk -F: '{print $$NF}'); \
	export LIVE_XKMS_REST_URL=https://localhost:$${HOST_REST_PORT}; \
	export LIVE_XKMS_NOISE_ADDR=localhost:$${HOST_NOISE_PORT}; \
	export LIVE_XKMS_SPKI_PIN=$$(docker exec $$cid cat /etc/xkms/certs/spki.pin); \
	export LIVE_XKMS_NOISE_KEY=$$(docker exec $$cid cat /etc/xkms/certs/noise.pub.hex); \
	export LIVE_XKMS_CA_PEM=/tmp/xkms-dev-ca.crt; \
	docker exec $$cid cat /etc/xkms/certs/ca.crt > $${LIVE_XKMS_CA_PEM}; \
	cd xkey/frontend && BASE_URL=http://localhost:34115 npx playwright test tests/e2e/live/ --reporter=list

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
	@$(GO) test -bench=. -benchmem -run=^$$ ./pkg/storage | tee -a $(BENCH_OUTPUT)
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
	@$(GO) test -bench=BenchmarkPKCS11 -benchmem -benchtime=3s -run=^$$ -tags=$(call go_tags,pkcs11) \
		./pkg/storage/hardware/... | tee $(BENCH_DIR)/pkcs11-certs.txt
	@echo "$(GREEN)✓ PKCS11 certificate benchmarks complete$(RESET)"
	@echo "$(CYAN)Results saved to: $(BENCH_DIR)/pkcs11-certs.txt$(RESET)"

.PHONY: bench-tpm2-certs
## bench-tpm2-certs: Benchmark TPM2 certificate storage operations
bench-tpm2-certs:
	@echo "$(CYAN)$(BOLD)→ Running TPM2 certificate storage benchmarks...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=BenchmarkTPM2 -benchmem -benchtime=3s -run=^$$ -tags=$(call go_tags,) \
		./pkg/storage/hardware/... | tee $(BENCH_DIR)/tpm2-certs.txt
	@echo "$(GREEN)✓ TPM2 certificate benchmarks complete$(RESET)"
	@echo "$(CYAN)Results saved to: $(BENCH_DIR)/tpm2-certs.txt$(RESET)"

.PHONY: bench-hybrid-certs
## bench-hybrid-certs: Benchmark hybrid certificate storage operations
bench-hybrid-certs:
	@echo "$(CYAN)$(BOLD)→ Running hybrid certificate storage benchmarks...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=BenchmarkHybrid -benchmem -benchtime=3s -run=^$$ -tags="$(call go_tags,pkcs11)" \
		./pkg/storage/hardware/... | tee $(BENCH_DIR)/hybrid-certs.txt
	@echo "$(GREEN)✓ Hybrid certificate benchmarks complete$(RESET)"
	@echo "$(CYAN)Results saved to: $(BENCH_DIR)/hybrid-certs.txt$(RESET)"

.PHONY: bench-cert-comparison
## bench-cert-comparison: Benchmark certificate storage comparison across backends
bench-cert-comparison:
	@echo "$(CYAN)$(BOLD)→ Running certificate storage comparison benchmarks...$(RESET)"
	@mkdir -p $(BENCH_DIR)
	@$(GO) test -bench=BenchmarkComparison -benchmem -benchtime=3s -run=^$$ -tags="$(call go_tags,pkcs11)" \
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
	@$(GO) test -bench=. -benchmem -run=^$$ -tags="$(call go_tags,pkcs11)" \
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
	@$(GO) test -bench=. -benchmem -run=^$$ -tags="$(call go_tags,pkcs11)" \
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
.PHONY: test-fido2-pkcs11
test-fido2-pkcs11:
	@$(MAKE) -C xkey test-fido2-pkcs11

.PHONY: integration-test-fido2-adapter
integration-test-fido2-adapter:
	@$(MAKE) -C xkey integration-test-fido2-adapter

.PHONY: integration-test-piv-pkcs11
integration-test-piv-pkcs11:
	@$(MAKE) -C xkey integration-test-piv-pkcs11

.PHONY: integration-test-xkey-pkcs11
## integration-test-xkey-pkcs11: Run xkey's PKCS#11 consumer tests (FIDO2 adapter + PIV)
# Renamed from integration-test-pkcs11, which collided with the core-library
# target above: make takes the LAST definition, so this recipe silently replaced
# it and the SoftHSM backend suite never ran under that name.
integration-test-xkey-pkcs11:
	@$(MAKE) -C xkey integration-test-pkcs11

.PHONY: playwright-test
playwright-test:
	@$(MAKE) -C xkey playwright-test

.PHONY: playwright-test-docker
playwright-test-docker:
	@$(MAKE) -C xkey playwright-test-docker

.PHONY: playwright-test-piv
playwright-test-piv:
	@$(MAKE) -C xkey playwright-test-piv

# test_dir resolves a test-%/coverage-% stem to its directory: a library
# package under pkg/ or a binary under cmd/ (make test-xkmsd). A stem naming
# neither is an error, never a silent "matched no packages" pass.
test_dir = $(or $(wildcard ./pkg/$(1)),$(wildcard ./cmd/$(1)),$(error neither ./pkg/$(1) nor ./cmd/$(1) exists))

# integration_dir does the same for integration-test-%: test/integration/$*.
integration_dir = $(or $(wildcard ./test/integration/$(1)),$(error ./test/integration/$(1) does not exist))

# pkg/acme/client's device-attest-01 DICE tests enroll the tfwsim-atecc608a
# simulator and fail without it, so the per-package targets that reach them
# build it first, as test-go, race and coverage-full do.
test-acme coverage-acme: agsim

# Dynamic test target for individual packages and binaries
# Usage: make test-backend, make test-xkms, make test-xkmsd, etc.
.PHONY: test-%
test-%:
	@echo "[36m→ Running tests for $(call test_dir,$*)...[0m"
	@$(GO) test -v $(TAG_FLAGS) $(call test_dir,$*)/...
	@echo "[32m✓ Tests passed for $(call test_dir,$*)[0m"

# Gadget integration tests live in xkey/ module — delegate to xkey Makefile.
.PHONY: integration-test-gadget
integration-test-gadget:
	@$(MAKE) -C xkey integration-test-gadget

# Dynamic integration test target for individual packages
# Usage: make integration-test-backend, make integration-test-pkcs11, etc.
.PHONY: integration-test-%
integration-test-%:
	@echo "[36m→ Running integration tests for $*...[0m"
	@$(GO) test -v -tags "$(call go_tags,integration $(BUILD_TAGS))" $(call integration_dir,$*)/...
	@echo "[32m✓ Integration tests passed for $*[0m"

# Dynamic coverage target for individual packages
# Usage: make coverage-backend, make coverage-xkms, etc.
.PHONY: coverage-%
coverage-%:
	@echo "[36m→ Generating coverage for $(call test_dir,$*)...[0m"
	@mkdir -p $(COVERAGE_DIR)
	@$(GO) test $(TAG_FLAGS) $(call test_dir,$*)/... -coverprofile=$(COVERAGE_DIR)/$*.out -covermode=atomic
	@$(GO) tool cover -html=$(COVERAGE_DIR)/$*.out -o $(COVERAGE_DIR)/$*-coverage.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/$*.out > $(COVERAGE_DIR)/$*.txt
	@TOTAL=$$(grep '^total:' $(COVERAGE_DIR)/$*.txt | awk '{print $$NF}'); \
	echo "[36m$* coverage: $${TOTAL}[0m"
	@echo "[32m✓ Coverage report: $(COVERAGE_DIR)/$*-coverage.html[0m"



# Builds never resolve through a workspace: modules come from Gitea tags
# (dependency-resolution.md §2). Immunizes against stray go.work files.
export GOWORK=off

# ---- dependency-resolution.md targets (2026-08-13 cutover) ----
# deps-latest runs before compiling in a consumer repo. release-alpha PREPARES
# a stated -alpha version of this repo as a pull request and stops
# (go-xkms#419); release-tag TAGS and publishes it once that pull request has
# been reviewed and merged (go-xkms#211). deps-latest picks the highest tag
# INCLUDING -alpha prereleases — bare 'go get @latest' ignores prereleases and
# would downgrade to legacy v0.0.0.
#
# The lockstep tag namespaces and the reciprocal go.mod pin edges are declared
# in scripts/release-alpha.sh, which owns them and which release-tag.sh
# sources rather than redeclaring. There is no second copy here to drift out
# of step with either.

.PHONY: release-alpha release-tag deps-latest

## release-alpha: PREPARE an -alpha release as a pull request. VERSION is
## REQUIRED. Publishes nothing -- it pushes only the release branch and
## opens its pull request, titled chore(release): vVERSION, on the forge the
## dev remote names, as the agent whose API token is in FORGE_TOKEN.
## Usage: FORGE_TOKEN=... make release-alpha VERSION=0.9.2-alpha [BUMP=minor] [DRY_RUN=1]
## The version is stated, never guessed; BUMP, when given, declares what kind
## of release this is and is refused unless it agrees with VERSION. Also
## refuses an effective PATCH bump that grew the exported Go API.
release-alpha:
	@bash scripts/release-alpha.sh --version "$(VERSION)" \
		$(if $(BUMP),--bump "$(BUMP)") \
		$(if $(DRY_RUN),--dry-run) \
		$(if $(RELEASE_REMOTE),--remote "$(RELEASE_REMOTE)")

## release-tag: TAG and publish a release already merged to main. VERSION is
## REQUIRED and must match the merged release commit's VERSION file exactly.
## Run this only after `make release-alpha`'s pull request has merged.
## Usage: make release-tag VERSION=0.9.2-alpha
release-tag:
	@bash scripts/release-tag.sh --version "$(VERSION)" \
		$(if $(RELEASE_REMOTE),--remote "$(RELEASE_REMOTE)")

deps-latest:
	@GOWORK=off sh -c ' \
	SELF=$$(go list -m); \
	for m in $$(go list -m -f "{{if not .Indirect}}{{.Path}}{{end}}" all 2>/dev/null | grep "^github.com/jeremyhahn/" | grep -vx "$$SELF"); do \
	  case "$$(go list -m -f "{{if .Replace}}{{.Replace.Path}}{{end}}" "$$m" 2>/dev/null)" in .*|/*) continue;; esac; \
	  V=$$(go list -m -versions "$$m" 2>/dev/null | tr " " "\n" | tail -1); \
	  if [ -n "$$V" ] && [ "$$V" != "$$m" ]; then go get "$$m@$$V" || exit 1; fi; \
	done; go mod tidy'
