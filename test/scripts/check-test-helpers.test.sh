#!/usr/bin/env bash
#
# Tests for scripts/check-test-helpers.sh: proves the check reports a
# production package that imports a test-only helper, names the importer,
# and stays quiet when only helpers and _test.go files import one. Everything
# runs against scratch Go modules under mktemp, never this repository.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/scripts/check-test-helpers.sh"
set +e
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n    want: %s\n    got:  %s\n' "$1" "$2" "$3" >&2; }
eq() { [ "$2" = "$3" ] && ok "$1" || no "$1" "$2" "$3"; }
section() { printf '\n%s\n' "$1"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export GOWORK=off GOFLAGS= GOCACHE="$WORK/gocache"

MOD=github.com/jeremyhahn/go-xkms/fixture

# newmod DIR writes a module whose helper package fixturetest is imported by
# its own tests only; callers then add the import under test.
newmod() {
	mkdir -p "$1/app" "$1/fixturetest"
	printf 'module %s\n\ngo 1.24\n' "$MOD" > "$1/go.mod"
	printf 'package fixturetest\n\nfunc Helper() int { return 1 }\n' > "$1/fixturetest/fixturetest.go"
	printf 'package app\n\nfunc Run() int { return 0 }\n' > "$1/app/app.go"
	printf 'package app\n\nimport (\n\t"testing"\n\n\t"%s/fixturetest"\n)\n\nfunc TestRun(t *testing.T) { _ = fixturetest.Helper() }\n' "$MOD" > "$1/app/app_test.go"
}

# --- a test-only import passes -------------------------------------------------
section "a helper imported only by tests"
CLEAN="$WORK/clean"
newmod "$CLEAN"
"$SCRIPT" "$CLEAN" >/dev/null 2>&1
eq "exits 0 when only _test.go files import the helper" "0" "$?"

# --- a helper importing a helper passes ----------------------------------------
section "a helper imported by another helper"
CHAIN="$WORK/chain"
newmod "$CHAIN"
mkdir -p "$CHAIN/apptest"
printf 'package apptest\n\nimport "%s/fixturetest"\n\nvar V = fixturetest.Helper()\n' "$MOD" > "$CHAIN/apptest/apptest.go"
"$SCRIPT" "$CHAIN" >/dev/null 2>&1
eq "exits 0 when the importer is itself a helper" "0" "$?"

# --- a production import fails and names the importer --------------------------
section "a production package importing a helper"
DIRTY="$WORK/dirty"
newmod "$DIRTY"
printf 'package app\n\nimport "%s/fixturetest"\n\nfunc Run() int { return fixturetest.Helper() }\n' "$MOD" > "$DIRTY/app/app.go"
OUT=$("$SCRIPT" "$DIRTY" 2>&1); RC=$?
eq "exits 1 when production code imports the helper" "1" "$RC"
eq "names the importer and the helper" "1" "$(grep -c "$MOD/app -> $MOD/fixturetest" <<<"$OUT")"

# --- a module that does not build is a failure, not a pass --------------------
section "a module that does not load"
BROKEN="$WORK/broken"
mkdir -p "$BROKEN"
"$SCRIPT" "$BROKEN" >/dev/null 2>&1
eq "exits 1 when go list fails" "1" "$?"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
exit $?
