#!/usr/bin/env bash
#
# Tests for scripts/check-public-literals.sh: the public-release readiness
# gate (go-xkms#1030) reads its rules from RELEASABILITY_PATTERNS at run time
# (DS-7983), the same `class<TAB>regex` text ci.yml's Releasability (private
# patterns) step reads, and never writes a rule or a matched value to its
# output. Everything here runs against synthetic scratch trees under mktemp
# with synthetic rules over documentation values (192.0.2.x, 198.51.100.x,
# example.com) -- it never points the script at this repository's own tree,
# so it cannot go red because something ELSE in the tree changed.
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

# The synthetic rules: a case-sensitive address rule, a case-insensitive host
# rule (`/i`) and a case-sensitive path rule, between a comment and a blank
# line, which are skipped.
TAB=$(printf '\t')
RULE_ADDR="lab-address${TAB}198\\.51\\.100\\.[0-9]{1,3}"
RULE_HOST="lab-host/i${TAB}kms-[0-9]+\\.example\\.com"
RULE_PATH="owner-path${TAB}/srv/acme-owner"
RULES=$(printf '# synthetic rules\n\n%s\n%s\n%s\n' "$RULE_ADDR" "$RULE_HOST" "$RULE_PATH")
RULES_CRLF=$(printf '# synthetic rules\r\n\r\n%s\r\n%s\r\n%s\r\n' "$RULE_ADDR" "$RULE_HOST" "$RULE_PATH")

# gate runs the script on a tree with the given rules.
gate() { RELEASABILITY_PATTERNS="$1" "$SCRIPT" "$2" 2>&1; }

# --- a clean tree passes ------------------------------------------------------
section "a clean tree"
CLEAN="$WORK/clean"
mkdir -p "$CLEAN/docs"
cat > "$CLEAN/docs/example.md" <<'EOF'
Contact the CA at ca.example.com from 192.0.2.10.
The owner path placeholder is $HOME/.config/xkey.
EOF
track "$CLEAN"
gate "$RULES" "$CLEAN" >/dev/null
eq "exits 0 on a clean tree" "0" "$?"

# --- each rule is applied, with its case ---------------------------------------
section "each rule is caught"
DIRTY="$WORK/dirty"
mkdir -p "$DIRTY"
echo "lab address: 198.51.100.42" > "$DIRTY/a.txt"
echo "lab host: KMS-07.EXAMPLE.COM" > "$DIRTY/b.txt"
echo "owner path: /SRV/ACME-OWNER/notes" > "$DIRTY/c.txt"
echo "owner path: /srv/acme-owner/notes" > "$DIRTY/d.txt"
track "$DIRTY"
OUT=$(gate "$RULES" "$DIRTY"); RC=$?
eq "exits 1 when a rule matches" "1" "$RC"
eq "reports the address file with path:line" "1" "$(grep -cx 'a.txt:1' <<<"$OUT")"
eq "a /i rule matches whatever the case" "1" "$(grep -cx 'b.txt:1' <<<"$OUT")"
eq "a rule without /i is case-sensitive" "0" "$(grep -c 'c\.txt' <<<"$OUT")"
eq "reports the path file" "1" "$(grep -cx 'd.txt:1' <<<"$OUT")"
eq "never prints a matched line's text" "0" "$(grep -ci 'lab address\|lab host\|owner path\|example\.com\|198\.51' <<<"$OUT")"
eq "never prints a rule" "0" "$(grep -c 'kms-\|acme-owner\|lab-address\|lab-host\|owner-path' <<<"$OUT")"

# --- CRLF rules read the same ---------------------------------------------------
section "CRLF rules"
OUT=$(gate "$RULES_CRLF" "$DIRTY"); RC=$?
eq "exits 1 with CRLF rules" "1" "$RC"
eq "a CRLF rule still matches (the CR is stripped)" "1" "$(grep -cx 'a.txt:1' <<<"$OUT")"
eq "the CRLF /i rule still matches" "1" "$(grep -cx 'b.txt:1' <<<"$OUT")"
eq "the CRLF path rule still matches" "1" "$(grep -cx 'd.txt:1' <<<"$OUT")"

# --- a line that cannot be used fails the parse, by number only ---------------
section "a bad rule line"
for bad in "no-tab-SECRETRULE" "lab-host${TAB}" "lab-host${TAB}(SECRETRULE" "${TAB}SECRETRULE"; do
	OUT=$(gate "$(printf '# c\n%s\n%s\n' "$RULE_ADDR" "$bad")" "$CLEAN"); RC=$?
	eq "a bad line fails the parse" "2" "$RC"
	eq "the error names line 3" "1" "$(grep -c 'line 3' <<<"$OUT")"
	eq "the error never quotes the line" "0" "$(grep -c 'SECRETRULE\|198' <<<"$OUT")"
done

# --- set but holding no rule is an error, unset is a notice --------------------
section "set but empty, and unset"
OUT=$(gate "" "$CLEAN"); RC=$?
eq "set but empty fails" "2" "$RC"
eq "says it holds no rule" "1" "$(grep -c 'no usable rule' <<<"$OUT")"
OUT=$(gate "$(printf '# only a comment\n\n')" "$CLEAN"); RC=$?
eq "only comments and blank lines fails" "2" "$RC"
OUT=$(env -u RELEASABILITY_PATTERNS "$SCRIPT" "$DIRTY" 2>&1); RC=$?
eq "unset exits 0" "0" "$RC"
eq "unset prints a notice" "1" "$(grep -c 'RELEASABILITY_PATTERNS is not set' <<<"$OUT")"

# --- untracked files are never read -------------------------------------------
# A staged credential file (gomodauth.env) is gitignored, never committed, and
# must never reach a public CI log.
section "untracked files are not scanned"
UNTRACKED="$WORK/untracked"
mkdir -p "$UNTRACKED"
echo "tracked and clean" > "$UNTRACKED/clean.txt"
track "$UNTRACKED"
echo "secret beside 198.51.100.42" > "$UNTRACKED/gomodauth.env"
OUT=$(gate "$RULES" "$UNTRACKED"); RC=$?
eq "an untracked match does not fail the gate" "0" "$RC"
eq "an untracked match is not reported" "0" "$(grep -c 'gomodauth.env\|secret' <<<"$OUT")"

# --- a tracked match on a later line ------------------------------------------
section "a tracked match is reported as path:line only"
TRACKED="$WORK/tracked"
mkdir -p "$TRACKED/sub"
printf 'first line\nsecret-value 198.51.100.42\n' > "$TRACKED/sub/conf.txt"
track "$TRACKED"
OUT=$(gate "$RULES" "$TRACKED"); RC=$?
eq "a tracked match fails the gate" "1" "$RC"
eq "the finding carries path:line" "1" "$(grep -cx 'sub/conf.txt:2' <<<"$OUT")"
eq "the finding omits the matched text" "0" "$(grep -c 'secret-value' <<<"$OUT")"

# --- a waived line is not reported --------------------------------------------
section "the InfoSec waiver marker"
WAIVER="$WORK/waiver"
mkdir -p "$WAIVER"
echo "198.51.100.7 lab-string-ok: documented example" > "$WAIVER/w.txt"
echo "198.51.100.8 lab-string-ok" > "$WAIVER/x.txt"
track "$WAIVER"
OUT=$(gate "$RULES" "$WAIVER"); RC=$?
eq "a marker without a reason still fails" "1" "$RC"
eq "a marker with a reason is not reported" "0" "$(grep -c 'w\.txt' <<<"$OUT")"
eq "the bare marker is reported" "1" "$(grep -cx 'x.txt:1' <<<"$OUT")"

# --- outside a git work tree the gate fails closed ----------------------------
section "a ROOT outside git fails closed"
NOGIT="$WORK/nogit"
mkdir -p "$NOGIT"
echo "secret beside 198.51.100.42" > "$NOGIT/h.txt"
OUT=$(GIT_CEILING_DIRECTORIES="$WORK" RELEASABILITY_PATTERNS="$RULES" "$SCRIPT" "$NOGIT" 2>&1); RC=$?
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
gate "$RULES" "$ALLOW" >/dev/null
eq "CLAUDE.md/AGENTS.md/.claude are excluded at any depth" "0" "$?"

# --- a path is read whole, whatever bytes its name holds ------------------------
# git grep -z hands over NUL-terminated paths; a name with a newline in it must
# reach the scan as one path, not as two that do not exist.
section "a file name with a newline"
NEWLINE="$WORK/newline"
mkdir -p "$NEWLINE"
echo "lab address: 198.51.100.9" > "$NEWLINE/odd"$'\n'"name.txt"
track "$NEWLINE"
gate "$RULES" "$NEWLINE" >/dev/null
eq "a match in a file whose name holds a newline fails the gate" "1" "$?"

# --- the rule files must be written, or the gate fails closed --------------------
# A rule that never reaches its file would be a rule never applied: a clean
# report on a dirty tree.
section "the rule files fail closed"
OUT=$(TMPDIR="$WORK/no-such-dir" RELEASABILITY_PATTERNS="$RULES" "$SCRIPT" "$DIRTY" 2>&1); RC=$?
eq "an unusable TMPDIR exits 2" "2" "$RC"
eq "says the rules could not be set up" "1" "$(grep -c 'rules' <<<"$OUT")"
eq "an unusable TMPDIR never quotes a rule" "0" "$(grep -cF -e '\.' -e 'acme-owner' <<<"$OUT")"
# A fake mktemp whose rule files are /dev/full: creating them succeeds, and
# every rule append fails with ENOSPC.
FAKEBIN="$WORK/fakebin"
mkdir -p "$FAKEBIN"
cat > "$FAKEBIN/mktemp" <<'EOF'
#!/usr/bin/env bash
d=$(PATH=${PATH#*:} mktemp "$@") || exit
ln -s /dev/full "$d/cs" && ln -s /dev/full "$d/ci" && echo "$d"
EOF
chmod +x "$FAKEBIN/mktemp"
OUT=$(PATH="$FAKEBIN:$PATH" RELEASABILITY_PATTERNS="$RULES" "$SCRIPT" "$DIRTY" 2>&1); RC=$?
eq "a failing rule write exits 2" "2" "$RC"
eq "names the rule line it could not write" "1" "$(grep -c 'line 3' <<<"$OUT")"
eq "a failing rule write never quotes a rule" "0" "$(grep -cF -e '\.' -e 'acme-owner' <<<"$OUT")"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
exit $?
