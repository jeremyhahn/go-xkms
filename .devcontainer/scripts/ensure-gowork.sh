#!/bin/bash
# ensure-gowork.sh — materialize the Go workspace used by every container that
# builds go-xkms (the devcontainer and the per-backend integration compose
# stacks under test/integration/*).
#
# go-xkms resolves its in-house modules through a Go workspace rather than
# published versions: the in-repo submodules (sdk/go, xkey) plus the sibling
# repos go-codec, go-frost, go-objstore, go-qrdb, go-quicraft and go-truststrap
# (the complete local closure — none of them pull further relative replaces).
# All six are bind-mounted at /go-<name>; with every in-house module present as
# a workspace member, only public dependencies are ever fetched, so no private
# git credentials are required inside the containers.
#
# This mirrors the canonical GOWORK_CONTENT/GOWORK_INIT defined in the top-level
# Makefile: the workspace is written to /tmp/go.work (NOT the bind-mounted repo,
# which must stay clean) and GOWORK is exported to point at it.
#
# Usage:
#   ensure-gowork.sh            # generate /tmp/go.work, populate /tmp/go.work.sum
#   ensure-gowork.sh <cmd>...   # ... then exec <cmd> (container entrypoint mode)
#
# The caller that does not pass a command (e.g. the Makefile devcontainer helper)
# must export GOWORK=/tmp/go.work itself for the subsequent go invocation.

set -euo pipefail

GOWORK_FILE=/tmp/go.work

# Locate the go-xkms repo root. Compose stacks set working_dir to /app or
# /workspace; honour an explicit override, otherwise probe the usual mounts.
detect_repo() {
	if [ -n "${GOWORK_REPO:-}" ] && [ -f "${GOWORK_REPO}/go.mod" ]; then
		echo "${GOWORK_REPO}"; return
	fi
	if [ -f "${PWD}/go.mod" ] && grep -q "module github.com/jeremyhahn/go-xkms$" "${PWD}/go.mod" 2>/dev/null; then
		echo "${PWD}"; return
	fi
	for d in /workspace /app; do
		if [ -f "${d}/go.mod" ]; then echo "${d}"; return; fi
	done
	echo "ensure-gowork: cannot locate go-xkms repo root (set GOWORK_REPO)" >&2
	exit 1
}

REPO="$(detect_repo)"

# The workspace go directive must match the modules' required Go version. A
# stale /tmp/go.work (e.g. left in a long-running devcontainer created before a
# Go-version bump) is regenerated rather than reused — otherwise `go` rejects it
# with "go.work lists go X, but module requires go >= Y".
GOWORK_GO_VERSION="1.26.4"
if [ -f "$GOWORK_FILE" ] && ! grep -qxF "go ${GOWORK_GO_VERSION}" "$GOWORK_FILE"; then
	echo "ensure-gowork: ${GOWORK_FILE} go directive is stale; regenerating for go ${GOWORK_GO_VERSION}" >&2
	rm -f "$GOWORK_FILE" "$GOWORK_FILE.sum"
fi

if [ ! -f "$GOWORK_FILE" ]; then
	for dir in /go-codec /go-frost /go-objstore /go-qrdb /go-qrdb/sdk/go \
		/go-quicraft /go-truststrap "${REPO}/sdk/go" "${REPO}/xkey"; do
		if [ ! -d "$dir" ]; then
			echo "ensure-gowork: required module directory not mounted: $dir" >&2
			echo "ensure-gowork: add the matching sibling bind mount to the compose stack" >&2
			exit 1
		fi
	done

	echo "ensure-gowork: generating ${GOWORK_FILE} (repo=${REPO})"
	cat > "$GOWORK_FILE" <<EOF
go ${GOWORK_GO_VERSION}

use (
	${REPO}
	${REPO}/sdk/go
	${REPO}/xkey
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
	github.com/jeremyhahn/go-frost v0.0.0 => /go-frost
	github.com/jeremyhahn/go-objstore v0.0.0 => /go-objstore
	github.com/jeremyhahn/go-qrdb v0.0.0 => /go-qrdb
	github.com/jeremyhahn/go-qrdb/sdk/go v0.0.0 => /go-qrdb/sdk/go
	github.com/jeremyhahn/go-quicraft v0.0.0 => /go-quicraft
	github.com/jeremyhahn/go-truststrap v0.0.0 => /go-truststrap
	github.com/jeremyhahn/go-xkms v0.0.0 => ${REPO}
	github.com/jeremyhahn/go-xkms/sdk/go v0.0.0 => ${REPO}/sdk/go
	github.com/jeremyhahn/go-xkms/xkey v0.0.0 => ${REPO}/xkey
)
EOF

	# Populate /tmp/go.work.sum for the workspace build list. Because every
	# in-house module is a local workspace member, this only fetches public
	# dependencies. `go mod download` does not rewrite any module's go.mod.
	echo "ensure-gowork: downloading module graph (populates go.work.sum)..."
	( cd "$REPO" && GOWORK="$GOWORK_FILE" go mod download all )
fi

export GOWORK="$GOWORK_FILE"

if [ "$#" -gt 0 ]; then
	exec "$@"
fi
