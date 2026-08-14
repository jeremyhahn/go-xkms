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
# Siblings are mounted at <SIBLING_ROOT>/go-<name>. The compose stacks mount
# them at the filesystem root, so SIBLING_ROOT defaults to empty and the paths
# come out as /go-<name> exactly as before. A devcontainer that checks the
# siblings out alongside the repo instead (…/sources/go-<name>) passes its
# parent directory as $4.
#
# Usage:
#   gen-gowork.sh [REPO_ROOT] [OUTPUT_FILE] [GO_VERSION] [SIBLING_ROOT]
# Defaults: REPO_ROOT=/workspace  OUTPUT_FILE=/tmp/go.work  GO_VERSION=1.26.5
#           SIBLING_ROOT=""  (i.e. siblings at /go-<name>)

set -euo pipefail

REPO_ROOT="${1:-/workspace}"
OUTPUT_FILE="${2:-/tmp/go.work}"
GO_VERSION="${3:-1.26.5}"
# Trailing slashes would produce /${SIBLING_ROOT}/go-codec; strip them so the generated paths
# are clean whichever form the caller passes.
SIBLING_ROOT="${4:-}"
SIBLING_ROOT="${SIBLING_ROOT%/}"

cat > "$OUTPUT_FILE" <<EOF
go ${GO_VERSION}

use (
	${REPO_ROOT}
	${REPO_ROOT}/sdk/go
	${REPO_ROOT}/xkey
	${SIBLING_ROOT}/go-codec
	${SIBLING_ROOT}/go-frost
	${SIBLING_ROOT}/go-objstore
	${SIBLING_ROOT}/go-qrdb
	${SIBLING_ROOT}/go-qrdb/sdk/go
	${SIBLING_ROOT}/go-quicraft
	${SIBLING_ROOT}/go-truststrap
)

replace (
	github.com/jeremyhahn/go-codec v0.0.0 => ${SIBLING_ROOT}/go-codec
	github.com/jeremyhahn/go-codec v1.3.0 => ${SIBLING_ROOT}/go-codec
	github.com/jeremyhahn/go-frost v0.0.0 => ${SIBLING_ROOT}/go-frost
	github.com/jeremyhahn/go-frost v0.1.4-alpha => ${SIBLING_ROOT}/go-frost
	github.com/jeremyhahn/go-frost v0.1.5-alpha => ${SIBLING_ROOT}/go-frost
	github.com/jeremyhahn/go-frost v0.1.6-alpha => ${SIBLING_ROOT}/go-frost
	github.com/jeremyhahn/go-objstore v0.0.0 => ${SIBLING_ROOT}/go-objstore
	github.com/jeremyhahn/go-objstore v0.1.5-alpha => ${SIBLING_ROOT}/go-objstore
	github.com/jeremyhahn/go-qrdb v0.0.0 => ${SIBLING_ROOT}/go-qrdb
	github.com/jeremyhahn/go-qrdb/sdk/go v0.0.0 => ${SIBLING_ROOT}/go-qrdb/sdk/go
	github.com/jeremyhahn/go-quicraft v0.0.0 => ${SIBLING_ROOT}/go-quicraft
	github.com/jeremyhahn/go-truststrap v0.0.0 => ${SIBLING_ROOT}/go-truststrap
	github.com/jeremyhahn/go-truststrap v0.1.1-alpha => ${SIBLING_ROOT}/go-truststrap
	github.com/jeremyhahn/go-xkms v0.0.0 => ${REPO_ROOT}
	github.com/jeremyhahn/go-xkms v0.2.2-alpha => ${REPO_ROOT}
	github.com/jeremyhahn/go-xkms/sdk/go v0.0.0 => ${REPO_ROOT}/sdk/go
	github.com/jeremyhahn/go-xkms/xkey v0.0.0 => ${REPO_ROOT}/xkey
)
EOF
