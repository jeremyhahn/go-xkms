#!/bin/sh
# pr-scope.sh -- classify a CI run for the two-tier pipeline (go-xkms
# #two-tier-pipeline). Called once, from the `changes` job in ci.yml, before
# anything else runs.
#
# Emits three GITHUB_OUTPUT values:
#
#   docs_only=true|false   every changed path is docs/markdown/changelog, so
#                          every Go job downstream (build, test, race,
#                          security, docker, the nested-module jobs, ...) can
#                          be skipped without leaving the required
#                          `CI / CI Gate` context red forever -- ci-gate
#                          treats a skip as success for exactly those jobs
#                          when docs_only is true.
#
#   full_tier=true|false   true for a push (main), a manual dispatch, or a
#                          pull_request whose head branch is train/* --
#                          these get the full matrix (race, every tagged
#                          backend, the raft matrix, nested-module tests,
#                          docker build+scan, security scan, and the 89%
#                          coverage gate). false is every other pull_request,
#                          which gets the fast tier instead (lint, build,
#                          changed-package tests, nested-module build+vet).
#
#   merge_base=<sha>|""    the commit this run's diff is measured against, so
#                          downstream jobs (test-changed,
#                          nested-module-build) can `git diff` against the
#                          exact same commit without recomputing it, and so a
#                          second job on a different runner host does not
#                          need this script's event-shaped inputs at all --
#                          just the sha, which is valid in any full clone of
#                          this repository.
#
# BOTH docs_only and merge_base FAIL OPEN: any error, or any ambiguity about
# what changed, resolves to docs_only=false (run the Go jobs) rather than
# docs_only=true (skip them and leave the gate green on an unreviewed
# change). A computation defect here costs runner-minutes, never gate
# coverage.
#
# Requires the checkout to run with fetch-depth: 0 (see ci.yml): a shallow
# clone can make the merge-base commit unreachable, and that must not be
# read as "nothing changed".
set -eu

out="${GITHUB_OUTPUT:?GITHUB_OUTPUT must be set (run from a GitHub/Gitea Actions step)}"

# --- Tier -----------------------------------------------------------------
# Non-pull_request events (push to main, workflow_dispatch) always get the
# full tier: main requires it, and a manual dispatch is rare enough that
# erring toward "run everything" costs nothing. A pull_request gets it only
# when its head branch is train/* -- see the top-of-file note in ci.yml for
# why trains, not every PR, carry the full matrix.
full_tier=true
if [ "${EVENT_NAME:-}" = "pull_request" ]; then
	case "${HEAD_REF:-}" in
	train/*) full_tier=true ;;
	*) full_tier=false ;;
	esac
fi
echo "full_tier=${full_tier}" >>"$out"

# --- Base commit ------------------------------------------------------------
base=""
case "${EVENT_NAME:-}" in
pull_request) base="${BASE_SHA:-}" ;;
push) base="${BEFORE_SHA:-}" ;;
esac

# BEFORE_SHA is all-zeros on a branch's first push; BASE_SHA is empty outside
# pull_request (workflow_dispatch, or a pull_request event with a payload
# this script has not seen). Either way there is no base to diff against:
# fail open on both outputs.
case "$base" in
"" | 0000000000000000000000000000000000000000)
	echo "pr-scope: no usable base sha (event=${EVENT_NAME:-unknown}); treating as code-changed" >&2
	echo "docs_only=false" >>"$out"
	echo "merge_base=" >>"$out"
	exit 0
	;;
esac

if ! git cat-file -e "${base}^{commit}" 2>/dev/null; then
	echo "pr-scope: base sha ${base} not reachable from this checkout (shallow clone?); treating as code-changed" >&2
	echo "docs_only=false" >>"$out"
	echo "merge_base=" >>"$out"
	exit 0
fi

merge_base="$(git merge-base "$base" HEAD)"
echo "merge_base=${merge_base}" >>"$out"

# --- Docs-only classification -----------------------------------------------
files="$(git diff --name-only "$merge_base" HEAD)"

if [ -z "$files" ]; then
	echo "pr-scope: no changed files against ${merge_base}; treating as code-changed" >&2
	echo "docs_only=false" >>"$out"
	exit 0
fi

echo "pr-scope: changed files against ${merge_base}:" >&2
printf '%s\n' "$files" >&2

# Remove every doc-like path (docs/, xkey/docs/, .changelog/, or any *.md);
# whatever is left is code. A path this list has never seen (a new top-level
# directory, say) is NOT doc-like by default -- it survives the grep -v and
# correctly forces docs_only=false, which is the fail-open direction.
non_docs="$(printf '%s\n' "$files" | grep -v -E '^(docs/|xkey/docs/|\.changelog/)|\.md$' || true)"

if [ -z "$non_docs" ]; then
	echo "docs_only=true" >>"$out"
else
	echo "pr-scope: non-doc paths:" >&2
	printf '%s\n' "$non_docs" >&2
	echo "docs_only=false" >>"$out"
fi
