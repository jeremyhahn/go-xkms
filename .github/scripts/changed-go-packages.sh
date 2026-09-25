#!/bin/sh
# changed-go-packages.sh -- pick the ROOT-MODULE Go packages the fast tier's
# "Unit Tests (changed packages)" job runs (ci.yml two-tier pipeline,
# go-xkms #two-tier-pipeline).
#
# sdk/go, xkey and web/desktop are separate Go modules; their fast-tier
# coverage is "build the module" (the nested-module-build job), not a
# package test run here, so changes under those trees are deliberately
# excluded from the set this script prints.
#
# Emits one GITHUB_OUTPUT value, `packages`: a space-separated list of `./...`
# import path patterns for `go test`, or the empty string when nothing under
# the root module's own tree changed.
#
# Best-effort reverse-dependency expansion: a single `go list -deps` over the
# root module's own package trees (cheap -- it type-checks without emitting
# code, see `go help list`) finds every package that imports a changed one,
# so a change to a leaf package like pkg/crypto/aead still exercises its
# direct callers, not only the leaf's own tests. This step is best-effort ON
# PURPOSE: if `go list` fails or reports nothing, the script FAILS OPEN to
# the changed packages alone -- the "or otherwise the changed packages"
# fallback the design explicitly allows, not a job failure. This job is the
# FAST tier's smoke test; the full tier (every train PR, every push to main)
# always runs the authoritative, un-scoped `make coverage` before anything
# reaches main, so a narrower-than-ideal fast-tier scope costs a later signal
# on a train, never a gap in what actually gates main.
set -eu

out="${GITHUB_OUTPUT:?GITHUB_OUTPUT must be set (run from a GitHub/Gitea Actions step)}"

merge_base="${MERGE_BASE:-}"
if [ -z "$merge_base" ]; then
	echo "changed-go-packages: no merge-base available; nothing to scope" >&2
	echo "packages=" >>"$out"
	exit 0
fi

files="$(git diff --name-only "$merge_base" HEAD -- '*.go' | grep -v -E '^(sdk/go/|xkey/|web/desktop/)' || true)"

if [ -z "$files" ]; then
	echo "changed-go-packages: no root-module .go changes" >&2
	echo "packages=" >>"$out"
	exit 0
fi

dirs="$(printf '%s\n' "$files" | xargs -r -n1 dirname | sort -u)"
changed_pkgs=""
for d in $dirs; do
	changed_pkgs="$changed_pkgs ./$d"
done
echo "changed-go-packages: changed packages:${changed_pkgs}" >&2

result="$changed_pkgs"

# Reverse-dependency expansion. Every step below is allowed to fail or find
# nothing; `result` already holds the fallback value.
if command -v go >/dev/null 2>&1; then
	changed_import_paths="$(go list $changed_pkgs 2>/dev/null || true)"
	all_with_deps="$(go list -deps -f '{{.ImportPath}} {{join .Deps ","}}' ./pkg/... ./cmd/... 2>/dev/null || true)"
	if [ -n "$changed_import_paths" ] && [ -n "$all_with_deps" ]; then
		reverse="$(printf '%s\n' "$all_with_deps" | while IFS=' ' read -r pkg deps; do
			for c in $changed_import_paths; do
				case ",$deps," in
				*",$c,"*)
					echo "$pkg"
					break
					;;
				esac
			done
		done)"
		if [ -n "$reverse" ]; then
			for p in $reverse; do
				case "$p" in
				github.com/jeremyhahn/go-xkms) rel="." ;;
				github.com/jeremyhahn/go-xkms/*) rel="${p#github.com/jeremyhahn/go-xkms/}" ;;
				*) continue ;; # outside this module; go list was scoped to ./pkg/... ./cmd/... so this should not happen
				esac
				result="$result ./$rel"
			done
			echo "changed-go-packages: reverse dependents:" >&2
			printf '%s\n' "$reverse" >&2
		fi
	fi
fi

packages="$(printf '%s\n' $result | sort -u | tr '\n' ' ')"

# Drop packages with no Go files under the tags the test step builds with
# (GO_TEST_TAGS, set by the workflow to the step's -tags value). The cloud
# and HSM backends (awskms, azurekv, gcpkms, vault, ...) are gated entirely
# behind their own build tags; handing one to `go test` without its tag is
# a "[setup failed]: build constraints exclude all Go files" error, not a
# skip. Those packages run with their tags in the full tier. Like the
# expansion above, this fails open: if `go list` is unavailable or reports
# nothing, the set is left as it was.
if [ -n "$packages" ] && command -v go >/dev/null 2>&1; then
	listed="$(go list -e -tags "${GO_TEST_TAGS:-}" -f '{{.ImportPath}} {{len .GoFiles}} {{len .CgoFiles}} {{len .TestGoFiles}} {{len .XTestGoFiles}}' $packages 2>/dev/null || true)"
	if [ -n "$listed" ]; then
		kept=""
		dropped=""
		while IFS=' ' read -r p gofiles cgofiles tests xtests; do
			[ -n "$p" ] || continue
			case "$p" in
			github.com/jeremyhahn/go-xkms) rel="." ;;
			github.com/jeremyhahn/go-xkms/*) rel="./${p#github.com/jeremyhahn/go-xkms/}" ;;
			*) continue ;;
			esac
			if [ "$((gofiles + cgofiles + tests + xtests))" -eq 0 ]; then
				dropped="$dropped $rel"
			else
				kept="$kept $rel"
			fi
		done <<LISTED
$listed
LISTED
		if [ -n "$dropped" ]; then
			echo "changed-go-packages: no Go files under tags '${GO_TEST_TAGS:-}' (tested by the full tier):${dropped}" >&2
		fi
		packages="$(printf '%s\n' $kept | sort -u | tr '\n' ' ')"
	fi
fi
# Trim trailing whitespace so a caller comparing against "" for "nothing to
# do" is not defeated by a lone space.
packages="$(printf '%s' "$packages" | sed 's/[[:space:]]*$//')"
echo "changed-go-packages: final package set: ${packages}" >&2
echo "packages=${packages}" >>"$out"
