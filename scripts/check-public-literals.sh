#!/usr/bin/env bash
#
# check-public-literals.sh — public-release readiness gate (go-xkms#1030).
#
# Fails with path:line output if any tracked file in the tree contains an
# internal literal: a lab-network address, a fleet host name, an owner path.
# None of these may reach a published tree, and neither may the rules that
# find them: the gate reads its rules at run time from the environment
# variable RELEASABILITY_PATTERNS, the same private text ci.yml's
# Releasability (private patterns) step reads from the Actions secret
# (DS-7983, as go-quicbaas pkg/labstrings does). Its format:
#   - one rule per line, `class<TAB>regex` (POSIX extended), split at the
#     first tab; a class may end in `/i` for a case-insensitive rule;
#   - a blank line or a `#` line is skipped, and a trailing CR is stripped;
#   - a line that cannot be used (no tab, an empty class or regex, a regex
#     grep -E refuses) fails the parse, named by line number only, because
#     the text is private;
#   - a variable that is set but holds no usable rule is an error, not a
#     pass. An unset variable prints a notice and passes, as the CI step
#     does for a run without the secret.
# A matched line that carries the InfoSec waiver marker with its reason,
# "lab-string-ok: <reason>", is not reported, as in the CI step.
#
# Only tracked files are scanned: the gate keeps literals out of what is
# committed. An untracked file -- such as the gitignored
# build/docker/devcontainer/gomodauth.env that `make stage-gomodauth` writes
# with module credentials -- is never read, and a ROOT that is not a git work
# tree fails closed rather than falling back to a tree scan.
#
# A finding is reported as path:line only. The matched line's text is never
# printed, and neither is a rule: a match can sit beside a secret, and CI
# logs are public (CA m417).
#
# Usage: RELEASABILITY_PATTERNS=... scripts/check-public-literals.sh [ROOT]
#   ROOT defaults to the repository root. A second, throwaway ROOT (a scratch
#   git repository) and synthetic rules are how
#   test/scripts/check-public-literals.test.sh proves the gate fires on a
#   planted literal and stays quiet on a clean tree.
#   Exit: 0 clean (or no rules set), 1 findings, 2 unusable rules or ROOT.
set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

ME=check-public-literals.sh

if [ -z "${RELEASABILITY_PATTERNS+set}" ]; then
	echo "$ME: RELEASABILITY_PATTERNS is not set; the private rules are not available to this run, so nothing was scanned" >&2
	exit 0
fi

# --- the rules --------------------------------------------------------------
# Each usable regex goes to one of two 0600 files, case-sensitive or `/i`.
# An error names the line by number and never quotes it.
RULES_DIR=$(mktemp -d)
chmod 700 "$RULES_DIR"
trap 'rm -rf "$RULES_DIR"' EXIT
RULES_CS="$RULES_DIR/cs"
RULES_CI="$RULES_DIR/ci"
(umask 077 && : >"$RULES_CS" && : >"$RULES_CI")
tab=$'\t'
n=0 bad=0 count=0
while IFS= read -r line || [ -n "$line" ]; do
	n=$((n + 1))
	line=${line%$'\r'}
	trimmed=${line#"${line%%[![:space:]]*}"}
	case $trimmed in '' | '#'*) continue ;; esac
	case $line in
	*"$tab"*) ;;
	*)
		echo "$ME: RELEASABILITY_PATTERNS line $n is not class<TAB>regex" >&2
		bad=1
		continue
		;;
	esac
	class=${line%%"$tab"*}
	re=${line#*"$tab"}
	if [ -z "$class" ] || [ "$class" = /i ]; then
		echo "$ME: RELEASABILITY_PATTERNS line $n has an empty class" >&2
		bad=1
		continue
	fi
	if [ -z "$re" ]; then
		echo "$ME: RELEASABILITY_PATTERNS line $n has an empty regex" >&2
		bad=1
		continue
	fi
	rc=0
	grep -E -e "$re" /dev/null >/dev/null 2>&1 || rc=$?
	if [ "$rc" -ge 2 ]; then
		echo "$ME: RELEASABILITY_PATTERNS line $n has a regex grep -E refuses" >&2
		bad=1
		continue
	fi
	case $class in
	*/i) printf '%s\n' "$re" >>"$RULES_CI" ;;
	*) printf '%s\n' "$re" >>"$RULES_CS" ;;
	esac
	count=$((count + 1))
done <<<"$RELEASABILITY_PATTERNS"
if [ "$bad" != 0 ]; then
	echo "$ME: RELEASABILITY_PATTERNS is malformed (line numbers above; the rules are not shown)" >&2
	exit 2
fi
if [ "$count" = 0 ]; then
	echo "$ME: RELEASABILITY_PATTERNS is set but holds no usable rule" >&2
	exit 2
fi

# --- the allowlist ---------------------------------------------------------
# Agent-instruction files are excluded on purpose, not left over from an
# incomplete scrub: CLAUDE.md/AGENTS.md and anything under .claude/ are
# agent-instruction files the owner publishes on their own schedule, and this
# repository's own CLAUDE.md forbids editing them from a task like this one.
# code-review.yml is the handbook's fleet workflow
# template, kept byte-identical to it outside its CUSTOMIZE lines (Company
# Agent m826); its comments and the opencode job's default OLLAMA_URL name
# fleet hosts, so it is excluded rather than edited away from the template.
PATHSPEC=(
	.
	':(exclude,glob)**/.claude/**'
	':(exclude,glob)**/CLAUDE.md'
	':(exclude,glob)**/AGENTS.md'
	':(exclude,glob)**/code-review.yml'
)

if ! git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	echo "check-public-literals.sh: not a git work tree, refusing to scan: $ROOT" >&2
	exit 2
fi

# git grep searches tracked files only. -l lists matching paths without their
# text, -z keeps paths verbatim, -I skips binary files, -E extended regex; -i
# only for the `/i` rules. An empty rules file is never passed: git grep
# refuses a run with no pattern.
files=
for rules in "$RULES_CS" "$RULES_CI"; do
	[ -s "$rules" ] || continue
	icase=
	[ "$rules" = "$RULES_CI" ] && icase=-i
	out=$(git -C "$ROOT" grep -lzIE $icase -f "$rules" -- "${PATHSPEC[@]}" | tr '\0' '\n')
	status=${PIPESTATUS[0]}
	if [ "$status" -gt 1 ]; then
		echo "$ME: git grep failed (exit $status)" >&2
		exit "$status"
	fi
	files+="$out"$'\n'
done

# lines prints the numbers of the lines of one file that a rule matches and
# that carry no waiver with a reason. grep on a single file prints
# "line:text"; cut keeps the line number and drops the text before anything
# reaches the log.
lines() {
	{
		[ -s "$RULES_CS" ] && grep -nE -f "$RULES_CS" -- "$1"
		[ -s "$RULES_CI" ] && grep -niE -f "$RULES_CI" -- "$1"
	} | grep -vE 'lab-string-ok:[[:space:]]*[[:alnum:]]' | cut -d: -f1 | sort -nu
}

found=0
while IFS= read -r path; do
	[ -n "$path" ] || continue
	while IFS= read -r line; do
		[ -n "$line" ] || continue
		if [ "$found" = 0 ]; then
			echo "$ME: internal literal(s) found (go-xkms#1030; path:line, the values are not shown):" >&2
			found=1
		fi
		printf '%s:%s\n' "$path" "$line" >&2
	done < <(lines "$ROOT/$path")
done < <(printf '%s' "$files" | sort -u)

if [ "$found" != 0 ]; then
	exit 1
fi
echo "$ME: clean -- $count private rule(s), no internal literals found" >&2
exit 0
