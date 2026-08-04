#!/bin/bash
# gen-gowork.sh — the SINGLE source of truth for the container Go workspace.
#
# Every container context that needs a build-time/run-time go.work (the main
# Dockerfile, the cluster xkmsd Dockerfile, the xkey e2e/fido2 entrypoints, and
# the devcontainer's ensure-gowork.sh) calls this script instead of inlining its
# own heredoc. That keeps the module set and — critically — the version-specific
# replace directives (go-objstore v0.1.5-alpha, go-frost v0.1.x-alpha, etc.) in
# ONE place, so they can never drift per-context the way they did historically.
#
# The replace set MUST mirror the canonical host workspace ~/sources/go.work. A
# bare `use` does not satisfy a pinned module version, so a v0.0.0-only replace
# makes the build fetch the published version and fail with "unknown revision".
#
# Siblings are always mounted at /go-<name> inside containers; the only thing
# that varies is the go-xkms repo root (/workspace, /build, or the devcontainer
# checkout), which is passed as $1.
#
# Usage:
#   gen-gowork.sh [REPO_ROOT] [OUTPUT_FILE] [GO_VERSION]
# Defaults: REPO_ROOT=/workspace  OUTPUT_FILE=/tmp/go.work  GO_VERSION=1.26.5

set -euo pipefail

REPO_ROOT="${1:-/workspace}"
OUTPUT_FILE="${2:-/tmp/go.work}"
GO_VERSION="${3:-1.26.5}"

cat > "$OUTPUT_FILE" <<EOF
go ${GO_VERSION}

use (
	${REPO_ROOT}
	${REPO_ROOT}/sdk/go
	${REPO_ROOT}/xkey
	/go-codec
	/go-frost
	/go-objstore
	/go-qrdb
	/go-qrdb/sdk/go
	/go-quicraft
	/go-truststrap
)

replace (
	github.com/jeremyhahn/go-codec v0.0.0 => /go-codec
	github.com/jeremyhahn/go-codec v1.3.0 => /go-codec
	github.com/jeremyhahn/go-frost v0.0.0 => /go-frost
	github.com/jeremyhahn/go-frost v0.1.4-alpha => /go-frost
	github.com/jeremyhahn/go-frost v0.1.5-alpha => /go-frost
	github.com/jeremyhahn/go-frost v0.1.6-alpha => /go-frost
	github.com/jeremyhahn/go-objstore v0.0.0 => /go-objstore
	github.com/jeremyhahn/go-objstore v0.1.5-alpha => /go-objstore
	github.com/jeremyhahn/go-qrdb v0.0.0 => /go-qrdb
	github.com/jeremyhahn/go-qrdb/sdk/go v0.0.0 => /go-qrdb/sdk/go
	github.com/jeremyhahn/go-quicraft v0.0.0 => /go-quicraft
	github.com/jeremyhahn/go-truststrap v0.0.0 => /go-truststrap
	github.com/jeremyhahn/go-truststrap v0.1.1-alpha => /go-truststrap
	github.com/jeremyhahn/go-xkms v0.0.0 => ${REPO_ROOT}
	github.com/jeremyhahn/go-xkms v0.2.2-alpha => ${REPO_ROOT}
	github.com/jeremyhahn/go-xkms/sdk/go v0.0.0 => ${REPO_ROOT}/sdk/go
	github.com/jeremyhahn/go-xkms/xkey v0.0.0 => ${REPO_ROOT}/xkey
)
EOF
