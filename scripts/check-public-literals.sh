#!/usr/bin/env bash
#
# check-public-literals.sh — public-release readiness gate (go-xkms#1030).
#
# Fails with file:line output if any file in the tree contains an internal
# literal: a lab-network address, a fleet host name, or an owner workstation
# path. None of these may reach a published tree. The placeholders that
# replace them are documented in CLAUDE.md's feature-docs convention and in
# the release-engineering docs:
#   - lab subnet 198.51.100.0/24        -> 192.0.2.x (RFC 5737 TEST-NET-1)
#   - fleet host names (dellemc-*, ...)   -> kms.example.com / ca.example.com
#   - owner workstation paths            -> $HOME/... or $XDG_CONFIG_HOME/...
#
# Generic private-range examples used as test data (192.168.1.1, 10.0.0.1,
# etc.) are NOT internal and must not be flagged -- only the lab's own
# subnet is.
#
# omega* is matched as the single known literal "omega-docker", not a
# wildcard: bare "omega" is an ordinary word (it is, among other things, a
# public gTLD baked into the vendored swagger-ui bundle under
# pkg/acme/api/swagger/, and an unrelated test fixture value in two xkey SSH
# tests). A wildcard here would flag both as false positives. If another
# omega-prefixed runner name shows up, add its literal string to PATTERN
# below rather than widening the match.
#
# Only tracked files are scanned: the gate keeps literals out of what is
# committed. An untracked file -- such as the gitignored
# build/docker/devcontainer/gomodauth.env that `make stage-gomodauth` writes
# with module credentials -- is never read, and a ROOT that is not a git work
# tree fails closed rather than falling back to a tree scan.
#
# A finding is reported as path:line only. The matched line's text is never
# printed: a match can sit beside a secret, and CI logs are public (CA m417).
#
# Usage: scripts/check-public-literals.sh [ROOT]
#   ROOT defaults to the repository root. A second, throwaway ROOT (a scratch
#   git repository) is how test/scripts/check-public-literals.test.sh proves
#   the gate fires on a planted literal and stays quiet on a clean tree.
set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

PATTERN='192\.168\.101\.[0-9]{1,3}|dellemc-?[0-9]*|omega-docker|/home/jhahn|~jhahn'

# --- the allowlist ---------------------------------------------------------
# Agent-instruction files are excluded on purpose, not left over from an
# incomplete scrub: CLAUDE.md/AGENTS.md and anything under .claude/ are
# agent-instruction files the owner publishes on their own schedule, and this
# repository's own CLAUDE.md forbids editing them from a task like this one.
# This script excludes itself because PATTERN's own text would otherwise
# match its own source. code-review.yml is the handbook's fleet workflow
# template, kept byte-identical to it outside its CUSTOMIZE lines (Company
# Agent m826); its comments and the opencode job's default OLLAMA_URL name
# fleet hosts, so it is excluded rather than edited away from the template.
PATHSPEC=(
	.
	':(exclude,glob)**/.claude/**'
	':(exclude,glob)**/CLAUDE.md'
	':(exclude,glob)**/AGENTS.md'
	':(exclude,glob)**/check-public-literals.sh'
	':(exclude,glob)**/code-review.yml'
)

if ! git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	echo "check-public-literals.sh: not a git work tree, refusing to scan: $ROOT" >&2
	exit 2
fi

# git grep searches tracked files only. -l lists matching paths without their
# text, -z keeps paths verbatim, -I skips binary files, -i is case-insensitive
# (DellEMC/dellemc/DELLEMC are all the same fleet prefix), -E extended regex.
files=$(git -C "$ROOT" grep -lzIiE -e "$PATTERN" -- "${PATHSPEC[@]}" | tr '\0' '\n')
status=$?

case "$status" in
0)
	echo "check-public-literals.sh: internal literal(s) found (go-xkms#1030):" >&2
	# grep on a single file prints "line:text"; cut keeps the line number and
	# drops the text before anything reaches the log.
	while IFS= read -r path; do
		grep -niE -e "$PATTERN" -- "$ROOT/$path" | cut -d: -f1 |
			while IFS= read -r line; do
				printf '%s:%s\n' "$path" "$line" >&2
			done
	done <<<"$files"
	exit 1
	;;
1)
	echo "check-public-literals.sh: clean -- no internal literals found" >&2
	exit 0
	;;
*)
	echo "check-public-literals.sh: git grep failed (exit $status)" >&2
	exit "$status"
	;;
esac
