#!/usr/bin/env bash
#
# Tests for scripts/go-test-each.sh, driven against a fake `go` (via $GO) whose
# behaviour is chosen by the package name, so no real build runs (m1261).
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/scripts/go-test-each.sh"
set +e
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n    want: %s\n    got:  %s\n' "$1" "$2" "$3" >&2; }
eq() { [ "$2" = "$3" ] && ok "$1" || no "$1" "$2" "$3"; }
section() { printf '\n%s\n' "$1"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export STATE="$WORK/state"
mkdir -p "$STATE"

# fake go test [FLAG...] -coverprofile=FILE PKG — records its flags and
# GOTMPDIR, counts earlier runs' GOTMPDIRs still on disk, leaves a file in
# GOTMPDIR, tracks how many runs overlap, then acts
# on PKG: pass* writes one block, fail* writes one block and exits 1, notest
# writes only the mode line, broken exits 2 without a profile.
FAKE="$WORK/go"
cat > "$FAKE" <<'EOF'
#!/usr/bin/env bash
shift
profile="" pkg="" flags=()
for a in "$@"; do
	case "$a" in
	-coverprofile=*) profile="${a#-coverprofile=}" ;;
	-*) flags+=("$a") ;;
	*) pkg="$a" ;;
	esac
done
echo "${flags[*]}" > "$STATE/flags.$pkg"
stale=0
for f in "$STATE"/gotmpdir.*; do [ -e "$f" ] && [ -e "$(cat "$f")" ] && stale=$((stale + 1)); done
echo "$stale" >> "$STATE/stale"
echo "$GOTMPDIR" > "$STATE/gotmpdir.$pkg"
touch "$GOTMPDIR/_pkg_.a"
touch "$STATE/running.$pkg"
ls "$STATE" | grep -c '^running\.' >> "$STATE/overlap"
sleep 0.2
rm "$STATE/running.$pkg"
echo "=== RUN $pkg"
case "$pkg" in
pass*) printf 'mode: atomic\n%s/a.go:1.1,2.2 1 1\n' "$pkg" > "$profile"; echo "ok $pkg" ;;
fail*) printf 'mode: atomic\n%s/a.go:1.1,2.2 1 0\n' "$pkg" > "$profile"; echo "--- FAIL $pkg"; exit 1 ;;
notest) echo 'mode: atomic' > "$profile"; echo "? $pkg [no test files]" ;;
broken) echo "$pkg: build failed"; exit 2 ;;
esac
EOF
chmod +x "$FAKE"
export GO="$FAKE"

reset() { rm -rf "$STATE"; mkdir -p "$STATE"; }

# --- passing packages merge into one profile ---------------------------------
section "merge"
reset
OUT=$("$SCRIPT" --coverprofile "$WORK/m/cover.out" -race -v -- pass1 notest pass2 2>&1); RC=$?
eq "exits 0 when every package passes" "0" "$RC"
eq "the merged profile has one mode line" "1" "$(grep -c '^mode:' "$WORK/m/cover.out")"
eq "the mode line comes first" "mode: atomic" "$(head -1 "$WORK/m/cover.out")"
eq "blocks keep argument order" "pass1/a.go:1.1,2.2 1 1 pass2/a.go:1.1,2.2 1 1" "$(tail -n +2 "$WORK/m/cover.out" | tr '\n' ' ' | sed 's/ $//')"
eq "go test flags pass through untouched" "-race -v" "$(cat "$STATE/flags.pass1")"
eq "every package's output is printed" "3" "$(grep -c '^=== RUN' <<<"$OUT")"

# --- each run's GOTMPDIR is its own and is removed ---------------------------
section "GOTMPDIR per package"
eq "each package gets its own GOTMPDIR" "3" "$(cat "$STATE"/gotmpdir.* | sort -u | wc -l | tr -d ' ')"
reset
"$SCRIPT" --jobs 1 --coverprofile "$WORK/g/cover.out" -- pass1 pass2 pass3 >/dev/null 2>&1
eq "a run's GOTMPDIR is gone before the next run starts" "0" "$(sort -n "$STATE/stale" | tail -1)"

# --- the job limit bounds concurrent runs ------------------------------------
section "jobs"
reset
"$SCRIPT" --jobs 2 --coverprofile "$WORK/j/cover.out" -- pass1 pass2 pass3 pass4 >/dev/null 2>&1
eq "no more than 2 runs overlap with --jobs 2" "2" "$(sort -n "$STATE/overlap" | tail -1)"
reset
"$SCRIPT" --jobs 1 --coverprofile "$WORK/j1/cover.out" -- pass1 pass2 pass3 >/dev/null 2>&1
eq "runs never overlap with --jobs 1" "1" "$(sort -n "$STATE/overlap" | tail -1)"

# --- failures surface the first failing package's exit code ------------------
section "failures"
reset
OUT=$("$SCRIPT" --coverprofile "$WORK/f/cover.out" -- pass1 broken fail1 2>&1); RC=$?
eq "exits with the first failing package's code" "2" "$RC"
eq "a failing package's output still reaches the caller" "1" "$(grep -c -- '--- FAIL fail1' <<<"$OUT")"
eq "profiles of packages that ran are still merged" "2" "$(tail -n +2 "$WORK/f/cover.out" | wc -l | tr -d ' ')"
reset
"$SCRIPT" --coverprofile "$WORK/f2/cover.out" -- fail1 broken >/dev/null 2>&1; RC=$?
eq "a test failure ahead of a build failure decides the code" "1" "$RC"

# --- argument validation -----------------------------------------------------
section "argument validation"
"$SCRIPT" -- pass1 >/dev/null 2>&1; RC=$?
eq "a missing --coverprofile is a usage error" "2" "$RC"
"$SCRIPT" --coverprofile "$WORK/v/cover.out" -race >/dev/null 2>&1; RC=$?
eq "no packages at all is a usage error" "2" "$RC"
"$SCRIPT" --jobs 0 --coverprofile "$WORK/v/cover.out" -- pass1 >/dev/null 2>&1; RC=$?
eq "--jobs 0 is refused" "2" "$RC"
"$SCRIPT" --jobs x --coverprofile "$WORK/v/cover.out" -- pass1 >/dev/null 2>&1; RC=$?
eq "a non-numeric --jobs is refused" "2" "$RC"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
exit $?
