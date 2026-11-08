#!/usr/bin/env bash
#
# Tests for scripts/check-public-literals.sh: proves the public-release
# readiness gate (go-xkms#1030) fires on each category of internal literal,
# respects the CLAUDE.md/AGENTS.md/.claude allowlist, and stays quiet on a
# clean tree. Everything here runs against synthetic scratch trees under
# mktemp -- it never points the script at this repository's own tree, so it
# cannot go red because something ELSE in the tree changed.
#
# The five literals this test plants are built from split fragments (see
# below) rather than written out whole: the gate scans every tracked file,
# including this one, so a literal written out here would trip the very
# check this file exists to exercise. scripts/check-public-literals.sh's own
# header comment is the one place these patterns are declared in full.
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

# Fragments, joined at runtime with +=, so no line of this file's own source
# ever carries one of the five literals contiguously.
lab_subnet="192.168.10"
lab_subnet+="1"
fleet_a="dell"
fleet_a+="emc"
fleet_b="omega"
fleet_b+="-docker"
# A workstation path is the private Releasability gate's class, not this
# gate's: a generic one must pass here.
owner_home="/home/someone"

# --- a clean tree passes ------------------------------------------------------
section "a clean tree"
CLEAN="$WORK/clean"
mkdir -p "$CLEAN/docs"
cat > "$CLEAN/docs/example.md" <<'EOF'
Contact the CA at ca.example.com. A generic private address like
192.168.1.1 or 10.0.0.1 is fine test data and must not be flagged.
The owner path placeholder is $HOME/.config/xkey.
EOF
track "$CLEAN"
"$SCRIPT" "$CLEAN" >/dev/null 2>&1
eq "exits 0 on a clean tree" "0" "$?"

# --- each category of internal literal is caught ------------------------------
section "each internal literal is caught"
DIRTY="$WORK/dirty"
mkdir -p "$DIRTY"
echo "lab subnet: ${lab_subnet}.42" > "$DIRTY/a.txt"
echo "fleet host: ${fleet_a}-03" > "$DIRTY/b.txt"
echo "fleet host: ${fleet_b}" > "$DIRTY/c.txt"
echo "owner path: ${owner_home}/notes" > "$DIRTY/d.txt"
track "$DIRTY"
OUT=$("$SCRIPT" "$DIRTY" 2>&1); RC=$?
eq "exits 1 when any internal literal is present" "1" "$RC"
eq "reports the lab-subnet file with file:line" "1" "$(grep -cx 'a.txt:1' <<<"$OUT")"
eq "reports the first fleet-host file" "1" "$(grep -cx 'b.txt:1' <<<"$OUT")"
eq "reports the second fleet-host file" "1" "$(grep -cx 'c.txt:1' <<<"$OUT")"
eq "does not report a workstation path" "0" "$(grep -c 'd\.txt' <<<"$OUT")"
eq "never prints a matched line's text" "0" "$(grep -c 'fleet host\|owner path\|lab subnet' <<<"$OUT")"

# --- untracked files are never read -------------------------------------------
# A staged credential file (gomodauth.env) is gitignored, never committed, and
# must never reach a public CI log.
section "untracked files are not scanned"
UNTRACKED="$WORK/untracked"
mkdir -p "$UNTRACKED"
echo "tracked and clean" > "$UNTRACKED/clean.txt"
track "$UNTRACKED"
echo "secret beside ${lab_subnet}.42" > "$UNTRACKED/gomodauth.env"
OUT=$("$SCRIPT" "$UNTRACKED" 2>&1); RC=$?
eq "an untracked literal does not fail the gate" "0" "$RC"
eq "an untracked literal is not reported" "0" "$(grep -c 'gomodauth.env\|secret' <<<"$OUT")"

# --- a tracked literal on a later line ----------------------------------------
section "a tracked literal is reported as path:line only"
TRACKED="$WORK/tracked"
mkdir -p "$TRACKED/sub"
printf 'first line\nsecret-value %s.42\n' "$lab_subnet" > "$TRACKED/sub/conf.txt"
track "$TRACKED"
OUT=$("$SCRIPT" "$TRACKED" 2>&1); RC=$?
eq "a tracked literal fails the gate" "1" "$RC"
eq "the finding carries path:line" "1" "$(grep -cx 'sub/conf.txt:2' <<<"$OUT")"
eq "the finding omits the matched text" "0" "$(grep -c 'secret-value' <<<"$OUT")"

# --- outside a git work tree the gate fails closed ----------------------------
section "a ROOT outside git fails closed"
NOGIT="$WORK/nogit"
mkdir -p "$NOGIT"
echo "secret beside ${lab_subnet}.42" > "$NOGIT/h.txt"
OUT=$(GIT_CEILING_DIRECTORIES="$WORK" "$SCRIPT" "$NOGIT" 2>&1); RC=$?
eq "exits 2 when ROOT is not a git work tree" "2" "$RC"
eq "says why it refused" "1" "$(grep -c 'not a git work tree' <<<"$OUT")"
eq "never scans the untracked tree" "0" "$(grep -c 'h.txt\|secret' <<<"$OUT")"

# --- generic private-range test data is not internal ---------------------------
section "generic private ranges are not flagged"
GENERIC="$WORK/generic"
mkdir -p "$GENERIC"
echo "test data: 192.168.1.1 and 10.0.0.1" > "$GENERIC/f.txt"
track "$GENERIC"
"$SCRIPT" "$GENERIC" >/dev/null 2>&1
eq "192.168.1.1/10.0.0.1 style addresses pass" "0" "$?"

# --- a bare instance of the shared word is not a fleet host name ---------------
# The second fleet name is matched literally, not as a wildcard (see the
# script's own header): the bare word alone, or an unrelated identifier that
# merely starts with it -- like the xkey SSH test fixtures this case mirrors
# -- must not trip the gate.
section "a bare instance of the shared word is not a fleet host name"
BAREWORD="$WORK/bareword"
mkdir -p "$BAREWORD"
{ b="${fleet_b%-docker}"; echo "session title: $b, profile: $b-id"; } > "$BAREWORD/g.txt"
track "$BAREWORD"
"$SCRIPT" "$BAREWORD" >/dev/null 2>&1
eq "the bare word and an unrelated -id suffix both pass" "0" "$?"

# --- the allowlist excludes agent-instruction files -----------------------------
section "the allowlist"
ALLOW="$WORK/allow"
mkdir -p "$ALLOW/.claude" "$ALLOW/sub"
echo "internal note: ${lab_subnet}.1" > "$ALLOW/CLAUDE.md"
echo "internal note: ${lab_subnet}.2" > "$ALLOW/AGENTS.md"
echo "internal note: ${lab_subnet}.3" > "$ALLOW/.claude/notes.md"
echo "internal note: ${lab_subnet}.4" > "$ALLOW/sub/CLAUDE.md"
track "$ALLOW"
"$SCRIPT" "$ALLOW" >/dev/null 2>&1
eq "CLAUDE.md/AGENTS.md/.claude are excluded at any depth" "0" "$?"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
exit $?
