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
# Usage: scripts/check-public-literals.sh [ROOT]
#   ROOT defaults to the repository root. A second, throwaway ROOT is how
#   test/scripts/check-public-literals.test.sh proves the gate fires on a
#   planted literal and stays quiet on a clean tree.
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
GREP_EXCLUDES=(
	--exclude-dir=.git   # ordinary checkout: .git is a directory
	--exclude=.git       # worktree checkout: .git is a plain gitdir-pointer file
	--exclude-dir=.claude
	--exclude=CLAUDE.md
	--exclude=AGENTS.md
	--exclude=check-public-literals.sh
	--exclude=code-review.yml
)

# -r recursive, -I skip binary files, -n line numbers, -i case-insensitive
# (DellEMC/dellemc/DELLEMC are all the same fleet prefix), -E extended regex.
matches=$(grep -rIniE "${GREP_EXCLUDES[@]}" "$PATTERN" "$ROOT")
status=$?

case "$status" in
0)
	echo "check-public-literals.sh: internal literal(s) found (go-xkms#1030):" >&2
	printf '%s\n' "$matches" | sed "s#^$ROOT/##" >&2
	exit 1
	;;
1)
	echo "check-public-literals.sh: clean -- no internal literals found" >&2
	exit 0
	;;
*)
	echo "check-public-literals.sh: grep failed (exit $status)" >&2
	exit "$status"
	;;
esac
