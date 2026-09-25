#!/usr/bin/env bash
#
# Tests for scripts/retry.sh: a fake command that fails a fixed number of
# times before succeeding, driven with --backoff 0 so the suite stays fast.
# Nothing here touches a real docker daemon or QEMU -- that is exactly the
# point: the bounded-attempt/backoff arithmetic is verified in isolation from
# whatever the wrapped command happens to be (go-xkms#1026).
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/scripts/retry.sh"
set +e
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n    want: %s\n    got:  %s\n' "$1" "$2" "$3" >&2; }
eq() { [ "$2" = "$3" ] && ok "$1" || no "$1" "$2" "$3"; }
section() { printf '\n%s\n' "$1"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# flaky N COUNTER_FILE — exits 1 on its first N-1 invocations (tracked in
# COUNTER_FILE, which retry.test.sh owns) and 0 from the Nth on.
FLAKY="$WORK/flaky.sh"
cat > "$FLAKY" <<'EOF'
#!/usr/bin/env bash
succeed_on="$1" counter_file="$2"
n=0
[ -f "$counter_file" ] && n=$(cat "$counter_file")
n=$((n + 1))
echo "$n" > "$counter_file"
if [ "$n" -lt "$succeed_on" ]; then
	echo "flaky: attempt $n < $succeed_on, failing" >&2
	exit 1
fi
echo "flaky: attempt $n, succeeding"
EOF
chmod +x "$FLAKY"

# --- succeeds within the attempt budget --------------------------------------
section "eventual success"
COUNTER="$WORK/c1"
OUT=$("$SCRIPT" --attempts 5 --backoff 0 -- "$FLAKY" 3 "$COUNTER" 2>&1); RC=$?
eq "exits 0 once the wrapped command finally succeeds" "0" "$RC"
eq "ran exactly 3 attempts, not all 5" "3" "$(cat "$COUNTER")"
eq "reports the eventual success" "1" "$(grep -c 'succeeding' <<<"$OUT")"

# --- exhausts its budget and surfaces the real exit code ---------------------
section "gives up"
COUNTER="$WORK/c2"
OUT=$("$SCRIPT" --attempts 2 --backoff 0 -- "$FLAKY" 5 "$COUNTER" 2>&1); RC=$?
eq "propagates the wrapped command's own failing exit code" "1" "$RC"
eq "ran exactly the requested 2 attempts, no more" "2" "$(cat "$COUNTER")"
eq "names the attempt budget in its last line" "1" "$(grep -c 'giving up after 2 attempts' <<<"$OUT")"

# --- default attempts/backoff apply with no flags ----------------------------
section "defaults"
COUNTER="$WORK/c3"
OUT=$("$SCRIPT" --backoff 0 -- "$FLAKY" 3 "$COUNTER" 2>&1); RC=$?
eq "the documented default of 3 attempts is enough for a 3rd-attempt success" "0" "$RC"
eq "used all 3 default attempts" "3" "$(cat "$COUNTER")"

# --- a command that always succeeds never retries -----------------------------
section "no retry when the first attempt succeeds"
COUNTER="$WORK/c4"
"$SCRIPT" --attempts 5 --backoff 0 -- "$FLAKY" 1 "$COUNTER" >/dev/null 2>&1
eq "exactly one attempt was made" "1" "$(cat "$COUNTER")"

# --- argument validation ------------------------------------------------------
# Usage/validation failures exit 2, distinct from a wrapped command's own
# (arbitrary) exit code, which retry.sh propagates unchanged (the "gives up"
# case above asserts exit 1 for exactly that reason).
section "argument validation"
OUT=$("$SCRIPT" --attempts 0 -- true 2>&1); RC=$?
eq "--attempts 0 is refused" "2" "$RC"
OUT=$("$SCRIPT" --attempts notanumber -- true 2>&1); RC=$?
eq "a non-numeric --attempts is refused" "2" "$RC"
OUT=$("$SCRIPT" 2>&1); RC=$?
eq "no command at all is a usage error" "2" "$RC"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
exit $?
