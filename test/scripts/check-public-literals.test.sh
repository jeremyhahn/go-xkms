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
OUT=$(env -u RELEASABILITY_PATTERNS -u RELEASABILITY_PATTERNS_FILE -u PUBLIC_LITERALS_SKIP make --no-print-directory -C "$ROOT" check-public-literals 2>&1); RC=$?
eq "the target exits non-zero with neither input set" "1" "$([ "$RC" -ne 0 ] && echo 1 || echo 0)"
eq "the refusal names RELEASABILITY_PATTERNS" "1" "$(grep -c 'refused.*RELEASABILITY_PATTERNS ' <<<"$OUT")"
eq "the refusal names RELEASABILITY_PATTERNS_FILE" "1" "$(grep -c 'refused.*RELEASABILITY_PATTERNS_FILE' <<<"$OUT")"

# A fork pull request has no secret: the CI caller sets the one documented
# opt-out, PUBLIC_LITERALS_SKIP=fork-pr, and the target announces the skip and
# passes. Any other value still refuses, so a typo never turns the gate off.
section "the fork opt-out is explicit"
OUT=$(env -u RELEASABILITY_PATTERNS -u RELEASABILITY_PATTERNS_FILE PUBLIC_LITERALS_SKIP=fork-pr make --no-print-directory -C "$ROOT" check-public-literals 2>&1); RC=$?
eq "PUBLIC_LITERALS_SKIP=fork-pr passes" "0" "$RC"
eq "the skip is announced" "1" "$(grep -c 'check-public-literals: skipped.*PUBLIC_LITERALS_SKIP=fork-pr' <<<"$OUT")"
OUT=$(env -u RELEASABILITY_PATTERNS -u RELEASABILITY_PATTERNS_FILE PUBLIC_LITERALS_SKIP=yes make --no-print-directory -C "$ROOT" check-public-literals 2>&1); RC=$?
eq "any other PUBLIC_LITERALS_SKIP value still refuses" "1" "$([ "$RC" -ne 0 ] && echo 1 || echo 0)"
eq "the wrong value is refused by name" "1" "$(grep -c 'refused.*PUBLIC_LITERALS_SKIP' <<<"$OUT")"
OUT=$(env -u RELEASABILITY_PATTERNS -u RELEASABILITY_PATTERNS_FILE PUBLIC_LITERALS_SKIP= make --no-print-directory -C "$ROOT" check-public-literals 2>&1); RC=$?
eq "an empty PUBLIC_LITERALS_SKIP still refuses" "1" "$([ "$RC" -ne 0 ] && echo 1 || echo 0)"
eq "the target never reports a skip" "0" "$(grep -ci 'skipped' <<<"$OUT")"
# With an input set the target hands the script's exit status through: a
# malformed list fails it, a list that matches nothing in the tree passes.
env -u RELEASABILITY_PATTERNS_FILE -u PUBLIC_LITERALS_SKIP RELEASABILITY_PATTERNS="no-tab-here" make --no-print-directory -C "$ROOT" check-public-literals >/dev/null 2>&1; RC=$?
eq "the target fails when the script fails" "1" "$([ "$RC" -ne 0 ] && echo 1 || echo 0)"
env -u RELEASABILITY_PATTERNS_FILE -u PUBLIC_LITERALS_SKIP RELEASABILITY_PATTERNS="lab-host${TAB}zq-nomatch-[0-9]{12}q" make --no-print-directory -C "$ROOT" check-public-literals >/dev/null 2>&1
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

# --- the lab-string-ok waiver, as in ci.yml's Releasability step ---------------
section "the lab-string-ok waiver"
WAIVED="$WORK/waived"
mkdir -p "$WAIVED"
printf 'fixture 198.51.100.9 // lab-string-ok: synthetic fixture\n' > "$WAIVED/a_test.go"
printf 'first\nhost SynthHost-5 # lab-string-ok:reason\n' > "$WAIVED/b.txt"
track "$WAIVED"
OUT=$("$SCRIPT" "$WAIVED" 2>&1); RC=$?
eq "only waived matches pass" "0" "$RC"
eq "waived lines are listed as path:line" "1" "$(grep -cx 'a_test.go:1' <<<"$OUT")"
eq "a waived line on a later line is listed" "1" "$(grep -cx 'b.txt:2' <<<"$OUT")"
eq "waived lines never print their text" "0" "$(grep -c 'fixture 198\|SynthHost' <<<"$OUT")"
BARE="$WORK/bare"
mkdir -p "$BARE"
printf 'fixture 198.51.100.9 // lab-string-ok:\n' > "$BARE/a.txt"
printf 'fixture 198.51.100.8 // lab-string-ok\n' > "$BARE/b.txt"
printf 'ok 198.51.100.7 // lab-string-ok: fine\n' > "$BARE/c.txt"
track "$BARE"
OUT=$("$SCRIPT" "$BARE" 2>&1); RC=$?
eq "a bare marker still fails" "1" "$RC"
eq "a marker with no reason is a finding" "1" "$(grep -cx 'a.txt:1' <<<"$OUT")"
eq "a marker with no colon is a finding" "1" "$(grep -cx 'b.txt:1' <<<"$OUT")"
eq "the waived line is not a finding" "0" "$(grep -A99 'internal literal' <<<"$OUT" | grep -cx 'c.txt:1')"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
exit $?
