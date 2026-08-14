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
GOWORK_GO_VERSION="1.26.5"
if [ -f "$GOWORK_FILE" ] && ! grep -qxF "go ${GOWORK_GO_VERSION}" "$GOWORK_FILE"; then
	echo "ensure-gowork: ${GOWORK_FILE} go directive is stale; regenerating for go ${GOWORK_GO_VERSION}" >&2
	rm -f "$GOWORK_FILE" "$GOWORK_FILE.sum"
fi

# Locate the sibling checkouts. The compose stacks bind-mount them at the
# filesystem root (/go-codec, …); a devcontainer that checks them out next to
# go-xkms instead has them at the repo's parent. Probing both means one script
# serves every context rather than each growing its own copy.
detect_sibling_root() {
	if [ -n "${GOWORK_SIBLING_ROOT:-}" ]; then
		echo "${GOWORK_SIBLING_ROOT%/}"; return
	fi
	if [ -d /go-codec ]; then echo ""; return; fi
	local parent
	parent="$(dirname "${REPO}")"
	if [ -d "${parent}/go-codec" ]; then echo "${parent}"; return; fi
	echo ""
}

SIBLING_ROOT="$(detect_sibling_root)"

if [ ! -f "$GOWORK_FILE" ]; then
	for dir in "${SIBLING_ROOT}/go-codec" "${SIBLING_ROOT}/go-frost" \
		"${SIBLING_ROOT}/go-objstore" "${SIBLING_ROOT}/go-qrdb" \
		"${SIBLING_ROOT}/go-qrdb/sdk/go" "${SIBLING_ROOT}/go-quicraft" \
		"${SIBLING_ROOT}/go-truststrap" "${REPO}/sdk/go" "${REPO}/xkey"; do
		if [ ! -d "$dir" ]; then
			echo "ensure-gowork: required module directory not mounted: $dir" >&2
			echo "ensure-gowork: add the matching sibling bind mount to the compose stack," >&2
			echo "ensure-gowork: or set GOWORK_SIBLING_ROOT to where the siblings live" >&2
			exit 1
		fi
	done

	echo "ensure-gowork: generating ${GOWORK_FILE} (repo=${REPO})"
	# Delegate to the single canonical generator so the module set and the
	# version-specific replace directives live in exactly one place (see
	# scripts/gen-gowork.sh). Never inline a go.work heredoc here again — that is
	# how the per-context copies drifted to stale/incomplete replaces.
	bash "${REPO}/scripts/gen-gowork.sh" "${REPO}" "${GOWORK_FILE}" "${GOWORK_GO_VERSION}" "${SIBLING_ROOT}"

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
