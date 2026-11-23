#!/usr/bin/env bash
#
# Tests for scripts/check-public-literals.sh: proves the public-release
# readiness gate (go-xkms#1030) reads its pattern list from an input
# (RELEASABILITY_PATTERNS or RELEASABILITY_PATTERNS_FILE), fails without one,
# rejects a malformed list, fires on each planted literal, respects the
# CLAUDE.md/AGENTS.md/.claude allowlist, and stays quiet on a clean tree.
# Everything here runs against synthetic scratch trees under mktemp with a
# synthetic pattern list built from documentation values (RFC 5737
# addresses, example.com-style names) -- it never points the script at this
# repository's own tree, so it cannot go red because something ELSE in the
# tree changed.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/scripts/check-public-literals.sh"
set +e
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n    want: %s\n    got:  %s\n' "$1" "$2" "$3" >&2; }
eq() { [ "$2" = "$3" ] && ok "$1" || no "$1" "$2" "$3"; }
section() { printf '\n%s\n' "$1"; }
# track makes a scratch tree a git repository with every file in it tracked:
# the gate scans tracked files only.
track() { git -C "$1" init -q && git -C "$1" add -A; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# The synthetic pattern list: one documentation-range address prefix and one
# made-up host name. Neither is a real value; the gate's real list is private.
TAB=$(printf '\t')
PATTERNS="# synthetic list
lab-address${TAB}198\\.51\\.100\\.[0-9]{1,3}

lab-host/i${TAB}synthhost-[0-9]+"
export RELEASABILITY_PATTERNS="$PATTERNS"
unset RELEASABILITY_PATTERNS_FILE

# --- a clean tree passes ------------------------------------------------------
section "a clean tree"
CLEAN="$WORK/clean"
mkdir -p "$CLEAN/docs"
cat > "$CLEAN/docs/example.md" <<'EOF'
Contact the CA at ca.example.com. Another documentation address like
192.0.2.10 or 203.0.113.5 is not on the list and must not be flagged.
EOF
track "$CLEAN"
"$SCRIPT" "$CLEAN" >/dev/null 2>&1
eq "exits 0 on a clean tree" "0" "$?"

# --- the pattern input is required ----------------------------------------------
section "the pattern list is an input"
OUT=$(env -u RELEASABILITY_PATTERNS -u RELEASABILITY_PATTERNS_FILE "$SCRIPT" "$CLEAN" 2>&1); RC=$?
eq "exits 2 with neither input set" "2" "$RC"
eq "names RELEASABILITY_PATTERNS" "1" "$(grep -c 'RELEASABILITY_PATTERNS ' <<<"$OUT")"
eq "names RELEASABILITY_PATTERNS_FILE" "1" "$(grep -c 'RELEASABILITY_PATTERNS_FILE' <<<"$OUT")"

# --- the Make target refuses without a pattern input (it never skips) ----------
# `make lint-gates` and the CI callers run the target: a notice-and-pass with
# no input would let them go green without checking a single literal.
section "the check-public-literals Make target needs the pattern input"
OUT=$(env -u RELEASABILITY_PATTERNS -u RELEASABILITY_PATTERNS_FILE make --no-print-directory -C "$ROOT" check-public-literals 2>&1); RC=$?
eq "the target exits non-zero with neither input set" "1" "$([ "$RC" -ne 0 ] && echo 1 || echo 0)"
eq "the refusal names RELEASABILITY_PATTERNS" "1" "$(grep -c 'refused.*RELEASABILITY_PATTERNS ' <<<"$OUT")"
eq "the refusal names RELEASABILITY_PATTERNS_FILE" "1" "$(grep -c 'refused.*RELEASABILITY_PATTERNS_FILE' <<<"$OUT")"
eq "the target never reports a skip" "0" "$(grep -ci 'skipped' <<<"$OUT")"
# With an input set the target hands the script's exit status through: a
# malformed list fails it, a list that matches nothing in the tree passes.
env -u RELEASABILITY_PATTERNS_FILE RELEASABILITY_PATTERNS="no-tab-here" make --no-print-directory -C "$ROOT" check-public-literals >/dev/null 2>&1; RC=$?
eq "the target fails when the script fails" "1" "$([ "$RC" -ne 0 ] && echo 1 || echo 0)"
env -u RELEASABILITY_PATTERNS_FILE RELEASABILITY_PATTERNS="lab-host${TAB}zq-nomatch-[0-9]{12}q" make --no-print-directory -C "$ROOT" check-public-literals >/dev/null 2>&1
eq "the target passes when the script passes" "0" "$?"

PFILE="$WORK/patterns.tsv"
printf '%s\n' "$PATTERNS" > "$PFILE"
DIRTYF="$WORK/dirtyf"
mkdir -p "$DIRTYF"
echo "host: synthhost-7" > "$DIRTYF/a.txt"
track "$DIRTYF"
OUT=$(env -u RELEASABILITY_PATTERNS RELEASABILITY_PATTERNS_FILE="$PFILE" "$SCRIPT" "$DIRTYF" 2>&1); RC=$?
eq "RELEASABILITY_PATTERNS_FILE is read" "1" "$RC"
eq "the file's pattern reports path:line" "1" "$(grep -cx 'a.txt:1' <<<"$OUT")"
OUT=$(env -u RELEASABILITY_PATTERNS RELEASABILITY_PATTERNS_FILE="$WORK/missing" "$SCRIPT" "$DIRTYF" 2>&1); RC=$?
eq "an unreadable pattern file exits 2" "2" "$RC"

# --- a malformed list fails without printing values -----------------------------
section "a malformed list"
OUT=$(RELEASABILITY_PATTERNS="lab-address 198\\.51\\.100\\." "$SCRIPT" "$CLEAN" 2>&1); RC=$?
eq "a line without a TAB exits 2" "2" "$RC"
eq "reports the line number" "1" "$(grep -c 'pattern line 1 is not' <<<"$OUT")"
eq "does not print the value" "0" "$(grep -c '198' <<<"$OUT")"
OUT=$(RELEASABILITY_PATTERNS="bogus${TAB}x" "$SCRIPT" "$CLEAN" 2>&1); RC=$?
eq "an unknown class exits 2" "2" "$RC"
OUT=$(RELEASABILITY_PATTERNS="lab-host${TAB}(" "$SCRIPT" "$CLEAN" 2>&1); RC=$?
eq "a regex grep -E refuses exits 2" "2" "$RC"
OUT=$(RELEASABILITY_PATTERNS="# only a comment" "$SCRIPT" "$CLEAN" 2>&1); RC=$?
eq "a list with no pattern line exits 2" "2" "$RC"

# --- each planted literal is caught ------------------------------------------------
section "each planted literal is caught"
DIRTY="$WORK/dirty"
mkdir -p "$DIRTY"
echo "net address: 198.51.100.42" > "$DIRTY/a.txt"
echo "host name: SynthHost-03" > "$DIRTY/b.txt"
echo "nothing to see" > "$DIRTY/c.txt"
track "$DIRTY"
OUT=$("$SCRIPT" "$DIRTY" 2>&1); RC=$?
eq "exits 1 when any listed literal is present" "1" "$RC"
eq "reports the address file with path:line" "1" "$(grep -cx 'a.txt:1' <<<"$OUT")"
eq "reports the host file, case-insensitively" "1" "$(grep -cx 'b.txt:1' <<<"$OUT")"
eq "does not report a clean file" "0" "$(grep -c 'c\.txt' <<<"$OUT")"
eq "never prints a matched line's text" "0" "$(grep -c 'net address\|host name' <<<"$OUT")"

# --- untracked files are never read -------------------------------------------
# A staged credential file (gomodauth.env) is gitignored, never committed, and
# must never reach a public CI log.
section "untracked files are not scanned"
UNTRACKED="$WORK/untracked"
mkdir -p "$UNTRACKED"
echo "tracked and clean" > "$UNTRACKED/clean.txt"
track "$UNTRACKED"
echo "secret beside 198.51.100.42" > "$UNTRACKED/gomodauth.env"
OUT=$("$SCRIPT" "$UNTRACKED" 2>&1); RC=$?
eq "an untracked literal does not fail the gate" "0" "$RC"
eq "an untracked literal is not reported" "0" "$(grep -c 'gomodauth.env\|secret' <<<"$OUT")"

# --- a tracked literal on a later line ----------------------------------------
section "a tracked literal is reported as path:line only"
TRACKED="$WORK/tracked"
mkdir -p "$TRACKED/sub"
printf 'first line\nsecret-value 198.51.100.42\n' > "$TRACKED/sub/conf.txt"
track "$TRACKED"
OUT=$("$SCRIPT" "$TRACKED" 2>&1); RC=$?
eq "a tracked literal fails the gate" "1" "$RC"
eq "the finding carries path:line" "1" "$(grep -cx 'sub/conf.txt:2' <<<"$OUT")"
eq "the finding omits the matched text" "0" "$(grep -c 'secret-value' <<<"$OUT")"

# --- outside a git work tree the gate fails closed ----------------------------
section "a ROOT outside git fails closed"
NOGIT="$WORK/nogit"
mkdir -p "$NOGIT"
echo "secret beside 198.51.100.42" > "$NOGIT/h.txt"
OUT=$(GIT_CEILING_DIRECTORIES="$WORK" "$SCRIPT" "$NOGIT" 2>&1); RC=$?
eq "exits 2 when ROOT is not a git work tree" "2" "$RC"
eq "says why it refused" "1" "$(grep -c 'not a git work tree' <<<"$OUT")"
eq "never scans the untracked tree" "0" "$(grep -c 'h.txt\|secret' <<<"$OUT")"

# --- the allowlist excludes agent-instruction files -----------------------------
section "the allowlist"
ALLOW="$WORK/allow"
mkdir -p "$ALLOW/.claude" "$ALLOW/sub"
echo "internal note: 198.51.100.1" > "$ALLOW/CLAUDE.md"
echo "internal note: 198.51.100.2" > "$ALLOW/AGENTS.md"
echo "internal note: 198.51.100.3" > "$ALLOW/.claude/notes.md"
echo "internal note: 198.51.100.4" > "$ALLOW/sub/CLAUDE.md"
track "$ALLOW"
"$SCRIPT" "$ALLOW" >/dev/null 2>&1
eq "CLAUDE.md/AGENTS.md/.claude are excluded at any depth" "0" "$?"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
exit $?
