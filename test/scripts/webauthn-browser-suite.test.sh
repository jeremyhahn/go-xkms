#!/usr/bin/env bash
#
# Tests for test/integration/webauthn-browser/run-suite.sh (CA m2529).
#
# The WebAuthn browser suite runs inside the devcontainer, so the only way the
# xkmsd log reaches the CI job log is for the suite's own command to print it.
# These tests run the wrapper against a stub `npx` on PATH in a copy of the
# suite directory: a failing run must print the log's tail under a header and
# keep Playwright's status; a passing run prints nothing extra. No Docker, no
# browser, no network.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/test/integration/webauthn-browser/run-suite.sh"
set +e
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n    want: %s\n    got:  %s\n' "$1" "$2" "$3" >&2; }
eq() { if [ "$2" = "$3" ]; then ok "$1"; else no "$1" "$2" "$3"; fi; }
has() { case "$3" in *"$2"*) ok "$1" ;; *) no "$1" "contains: $2" "$3" ;; esac; }
lacks() { case "$3" in *"$2"*) no "$1" "does not contain: $2" "$3" ;; *) ok "$1" ;; esac; }
section() { printf '\n%s\n' "$1"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# The suite directory: the wrapper and a runtime directory holding the log.
SUITE="$WORK/suite"
mkdir -p "$SUITE/.runtime"
cp "$SCRIPT" "$SUITE/run-suite.sh"

# The stub npx records its arguments, prints a line and exits $STUB_RC.
FAKEBIN="$WORK/bin"
mkdir -p "$FAKEBIN"
cat >"$FAKEBIN/npx" <<'EOF'
#!/bin/sh
echo "npx $*" >>"$STUB_LOG"
echo "stub playwright output"
exit "${STUB_RC:-0}"
EOF
chmod +x "$FAKEBIN/npx"

# A log longer than the printed tail: line 1 must not appear, the Error line
# near the end must.
{
	for i in $(seq 1 450); do echo "{\"level\":\"INFO\",\"msg\":\"line $i\"}"; done
	echo '{"level":"ERROR","msg":"webauthn registration failed","error":"stub cause"}'
} >"$SUITE/.runtime/xkmsd.log"

# run [ENV...] -- run the wrapper from another directory. Sets out, rc, calls.
run() {
	: >"$WORK/calls"
	out=$(cd "$WORK" && env PATH="$FAKEBIN:$PATH" STUB_LOG="$WORK/calls" "$@" bash "$SUITE/run-suite.sh" 2>&1)
	rc=$?
	calls=$(cat "$WORK/calls")
}

section "a failing suite prints the xkmsd log and keeps its status"
run STUB_RC=3
eq "exit status is Playwright's" 3 "$rc"
eq "it runs playwright test" "npx playwright test" "$calls"
has "it relays Playwright's output" "stub playwright output" "$out"
has "it prints a header" "last 400 lines of the xkmsd log" "$out"
has "it prints the Error line" '"level":"ERROR","msg":"webauthn registration failed"' "$out"
has "it prints the tail" '"msg":"line 450"' "$out"
lacks "it prints only the last 400 lines" '"msg":"line 51"}' "$out"

section "a passing suite prints nothing extra"
run STUB_RC=0
eq "exit 0" 0 "$rc"
has "it relays Playwright's output" "stub playwright output" "$out"
lacks "no header" "xkmsd log" "$out"
lacks "no log line" "webauthn registration failed" "$out"

section "a failing suite without a log says so and keeps its status"
rm -f "$SUITE/.runtime/xkmsd.log"
run STUB_RC=1
eq "exit status is Playwright's" 1 "$rc"
has "it says the log is missing" "no xkmsd log at" "$out"

# run-server.sh (Codex P1): the real script in a copy of the repository
# layout it reaches by relative path, against a stub daemon (XKMSD_BIN) and a
# stub barrier opener. Its stdout and stderr must reach both .runtime/xkmsd.log
# and the calling process, and each launch must truncate the previous log.
SRV_ROOT="$WORK/repo"
SRV_DIR="$SRV_ROOT/test/integration/webauthn-browser"
OPENER_DIR="$SRV_ROOT/build/docker/devcontainer/scripts"
mkdir -p "$SRV_DIR" "$OPENER_DIR"
cp "$ROOT/test/integration/webauthn-browser/run-server.sh" "$SRV_DIR/run-server.sh"
cat >"$OPENER_DIR/open-server-barrier.sh" <<'EOF'
#!/bin/sh
echo "stub opener $RUN_MARK"
EOF
cat >"$FAKEBIN/xkmsd" <<'EOF'
#!/bin/sh
if [ "${1:-}" = init ]; then
	echo "stub init $RUN_MARK"
	exit 0
fi
echo "stub daemon stdout $RUN_MARK"
echo "stub daemon stderr $RUN_MARK" >&2
exit 0
EOF
chmod +x "$FAKEBIN/xkmsd"

# serve MARK -- launch run-server.sh from another directory. Sets out, rc, log.
serve() {
	out=$(cd "$WORK" && env XKMSD_BIN="$FAKEBIN/xkmsd" RUN_MARK="$1" bash "$SRV_DIR/run-server.sh" 2>/dev/null)
	rc=$?
	log=$(cat "$SRV_DIR/.runtime/xkmsd.log" 2>/dev/null)
}

section "run-server.sh copies the daemon's stdout and stderr to the log and the caller"
serve first-run
eq "exit status is the daemon's" 0 "$rc"
has "the log holds the daemon's stdout" "stub daemon stdout first-run" "$log"
has "the log holds the daemon's stderr" "stub daemon stderr first-run" "$log"
has "the log holds the opener's output" "stub opener first-run" "$log"
has "the caller gets the daemon's stdout" "stub daemon stdout first-run" "$out"
has "the caller gets the daemon's stderr" "stub daemon stderr first-run" "$out"

section "a second launch truncates the previous log"
serve second-run
has "the log holds the second run" "stub daemon stdout second-run" "$log"
lacks "the first run is gone" "first-run" "$log"

printf '\npassed %d, failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
