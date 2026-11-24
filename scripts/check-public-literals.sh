#!/usr/bin/env bash
#
# check-public-literals.sh: public-release readiness gate for internal literals.
set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

PATTERN='192\.168\.101\.[0-9]{1,3}|dellemc-?[0-9]*|omega-docker'

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
