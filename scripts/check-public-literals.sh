#!/usr/bin/env bash
#
# check-public-literals.sh — public-release readiness gate (go-xkms#1030).
#
# Fails with path:line output if any tracked file contains a literal that
# matches the pattern list. The pattern list is an input, never part of this
# tree: the values it refuses are private, so they are not written here, not
# even as patterns to refuse. The list comes from one of:
#
#   RELEASABILITY_PATTERNS       the pattern text itself
#   RELEASABILITY_PATTERNS_FILE  a path to a file holding the same text
#
# The format is the one ci.yml's `Releasability (private patterns)` step
# parses from the Actions secret of the same name: blank and `#` lines are
# skipped; every other line is `class<TAB>regex`, where class is one of
# coord-host, internal-email, lab-address, lab-host or owner-path (an `/i`
# suffix is allowed) and regex is a POSIX extended regex. Matching is
# case-insensitive. A malformed line, an unknown class or a regex grep -E
# refuses fails the gate, reported by line number only. With neither input
# set the gate fails (exit 2) and names both variables.
#
# Docs and fixtures use documentation values instead: RFC 5737 addresses
# (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and example.com hosts.
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
NAME=check-public-literals.sh

# --- the pattern input -------------------------------------------------------
if [ -n "${RELEASABILITY_PATTERNS:-}" ]; then
	patterns=$RELEASABILITY_PATTERNS
elif [ -n "${RELEASABILITY_PATTERNS_FILE:-}" ]; then
	if [ ! -r "$RELEASABILITY_PATTERNS_FILE" ]; then
		echo "$NAME: RELEASABILITY_PATTERNS_FILE is not a readable file" >&2
		exit 2
	fi
	patterns=$(cat -- "$RELEASABILITY_PATTERNS_FILE")
else
	echo "$NAME: no pattern list: set RELEASABILITY_PATTERNS (class<TAB>regex lines) or RELEASABILITY_PATTERNS_FILE (a path to them)" >&2
	exit 2
fi

pf=$(mktemp)
chmod 600 "$pf"
trap 'rm -f "$pf"' EXIT
tab=$(printf '\t')
n=0 bad=0 count=0
while IFS= read -r line || [ -n "$line" ]; do
	n=$((n + 1))
	line=${line%$'\r'}
	trimmed=${line#"${line%%[![:space:]]*}"}
	case $trimmed in '' | '#'*) continue ;; esac
	case $line in
	*"$tab"*) ;;
	*)
		echo "$NAME: pattern line $n is not class<TAB>regex" >&2
		bad=1
		continue
		;;
	esac
	class=${line%%"$tab"*}
	re=${line#*"$tab"}
	case ${class%/i} in
	coord-host | internal-email | lab-address | lab-host | owner-path) ;;
	*)
		echo "$NAME: pattern line $n has an unknown class" >&2
		bad=1
		continue
		;;
	esac
	if [ -z "$re" ]; then
		echo "$NAME: pattern line $n has an empty regex" >&2
		bad=1
		continue
	fi
	rc=0
	grep -E -e "$re" /dev/null >/dev/null 2>&1 || rc=$?
	if [ "$rc" -ge 2 ]; then
		echo "$NAME: pattern line $n has a regex grep -E refuses" >&2
		bad=1
		continue
	fi
	printf '%s\n' "$re" >>"$pf"
	count=$((count + 1))
done <<<"$patterns"
if [ "$bad" != 0 ]; then
	echo "$NAME: the pattern list is malformed (line numbers above; the values are not shown)" >&2
	exit 2
fi
if [ "$count" = 0 ]; then
	echo "$NAME: the pattern list holds no class<TAB>regex line" >&2
	exit 2
fi

# --- the allowlist ---------------------------------------------------------
# Agent-instruction files are excluded on purpose: CLAUDE.md/AGENTS.md and
# anything under .claude/ are agent-instruction files the owner publishes on
# their own schedule. code-review.yml is the handbook's fleet workflow
# template, kept byte-identical to it outside its CUSTOMIZE lines (Company
# Agent m826), so it is excluded rather than edited away from the template.
PATHSPEC=(
	.
	':(exclude,glob)**/.claude/**'
	':(exclude,glob)**/CLAUDE.md'
	':(exclude,glob)**/AGENTS.md'
	':(exclude,glob)**/code-review.yml'
)

if ! git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	echo "$NAME: not a git work tree, refusing to scan: $ROOT" >&2
	exit 2
fi

# git grep searches tracked files only. -n prints path:line:text, -I skips
# binary files, -i is case-insensitive, -E extended regex, -f reads the
# patterns from the parsed list. The text stays in memory: cut keeps path:line.
rc=0
out=$(git -C "$ROOT" grep -nIiE -f "$pf" -- "${PATHSPEC[@]}") || rc=$?
case "$rc" in
0 | 1) ;;
*)
	echo "$NAME: git grep failed (exit $rc)" >&2
	exit "$rc"
	;;
esac

# The InfoSec waiver of ci.yml's Releasability step: a matched line carrying
# `lab-string-ok: <reason>` (colon and reason required) is listed, not failed.
waiver='lab-string-ok:[[:space:]]*[[:alnum:]]'
waived=$(printf '%s\n' "$out" | grep -E -e "$waiver" | cut -d: -f1,2 || true)
hits=$(printf '%s\n' "$out" | grep -v -E -e "$waiver" | grep -v '^$' | cut -d: -f1,2 || true)
unset out

if [ -n "$waived" ]; then
	nw=$(printf '%s\n' "$waived" | wc -l)
	echo "$NAME: $nw matched line(s) carry the lab-string-ok waiver (path:line):" >&2
	printf '%s\n' "$waived" >&2
fi
if [ -n "$hits" ]; then
	echo "$NAME: internal literal(s) found (go-xkms#1030):" >&2
	printf '%s\n' "$hits" >&2
	exit 1
fi
echo "$NAME: clean -- no internal literals found" >&2
exit 0
