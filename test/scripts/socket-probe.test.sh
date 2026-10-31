#!/usr/bin/env bash
#
# Tests for scripts/socket-probe.sh (DS-3769).
#
# The probe must say "connected" exactly when connect(2) on the socket
# succeeds, whatever the server then makes of curl's request, and must carry
# connect(2)'s error when it does not. These tests run the real curl against
# Unix sockets in a temporary directory. No Docker, no network.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/scripts/socket-probe.sh"
set +e
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n    want: %s\n    got:  %s\n' "$1" "$2" "$3" >&2; }
eq() { [ "$2" = "$3" ] && ok "$1" || no "$1" "$2" "$3"; }
has() { case "$3" in *"$2"*) ok "$1" ;; *) no "$1" "contains: $2" "$3" ;; esac; }

WORK=$(mktemp -d)
LISTENER=""
trap '[ -z "$LISTENER" ] || kill "$LISTENER" 2>/dev/null; rm -rf "$WORK"' EXIT

# run SOCKET [ENV=VALUE...] runs the probe on SOCKET (none when empty) and
# sets out and rc.
run() {
	local socket=$1
	shift
	out=$(env "$@" /bin/sh "$SCRIPT" ${socket:+"$socket"} 2>&1)
	rc=$?
}

# A listener that never accepts: the kernel completes connect(2) from the
# backlog and curl then waits for an answer that never comes, as it does on
# a TLS socket that ignores a plaintext request.
python3 -I -c '
import socket, sys, time
s = socket.socket(socket.AF_UNIX)
s.bind(sys.argv[1])
s.listen(8)
time.sleep(60)
' "$WORK/live.sock" &
LISTENER=$!
for _ in $(seq 1 50); do
	[ -S "$WORK/live.sock" ] && break
	sleep 0.1
done

printf '\na listening socket is connected\n'
run "$WORK/live.sock" XKMS_SOCKET_PROBE_TIMEOUT=1
eq "exit 0" 0 "$rc"
eq "it prints nothing" "" "$out"

printf '\na socket nobody listens on is refused\n'
python3 -I -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$WORK/dead.sock"
run "$WORK/dead.sock"
eq "exit 1" 1 "$rc"
has "it carries connect(2)'s error" "Connection refused" "$out"
has "it carries curl's summary" "curl: (7)" "$out"

printf '\na missing socket is named\n'
run "$WORK/missing.sock"
eq "exit 1" 1 "$rc"
has "it carries connect(2)'s error" "No such file or directory" "$out"

printf '\nno curl is said so\n'
mkdir -p "$WORK/nocurl"
run "$WORK/live.sock" PATH="$WORK/nocurl"
eq "exit 1" 1 "$rc"
has "it names the missing tool" "socket-probe: curl is not installed" "$out"

printf '\nno socket argument is a usage error\n'
run ""
[ "$rc" -ne 0 ] && ok "it fails" || no "it fails" "a non-zero exit" "$rc"
has "it prints the usage" "usage: socket-probe.sh SOCKET" "$out"

printf '\npassed %d, failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
