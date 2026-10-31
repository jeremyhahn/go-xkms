#!/usr/bin/env bash
#
# Tests for scripts/start-test-xkmsd.sh (DS-3769).
#
# The script serves the PKCS#11 suites' Unix socket. While the compose
# xkms-server runs it must only wait for that server's socket, never unlink it
# or start a second daemon on the path. Otherwise it starts its own xkmsd the
# supported way: `xkmsd init` with the SO PIN in the environment, a config with
# no secret in it, the daemon without the PIN, and an unseal through the real
# open-server-barrier.sh. These tests run it against fake go, xkmsd, curl
# (which also answers the real socket-probe.sh), getent and sleep on PATH, and record every call. No Docker, no network.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/scripts/start-test-xkmsd.sh"
set +e
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n    want: %s\n    got:  %s\n' "$1" "$2" "$3" >&2; }
eq() { [ "$2" = "$3" ] && ok "$1" || no "$1" "$2" "$3"; }
has() { case "$3" in *"$2"*) ok "$1" ;; *) no "$1" "contains: $2" "$3" ;; esac; }
lacks() { case "$3" in *"$2"*) no "$1" "does not contain: $2" "$3" ;; *) ok "$1" ;; esac; }
section() { printf '\n%s\n' "$1"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

PIN="stub-conformance-pin"
PIN_B64=$(printf '%s' "$PIN" | base64 -w0)
SEALED='{"sealed": true, "strategy": "passphrase", "hardware_backed": false, "cluster_seal": false, "initialized_at": "2026-10-11T00:00:00Z"}'

FAKEBIN="$WORK/bin"
mkdir -p "$FAKEBIN"

# The fake go records the build and installs the fake xkmsd at -o.
cat >"$FAKEBIN/go" <<'EOF'
#!/bin/bash
echo "go $*" >>"$STUB_LOG"
while [ $# -gt 0 ]; do
	[ "$1" = -o ] && out=$2
	shift
done
cp "$STUB_XKMSD" "$out"
chmod +x "$out"
EOF

# The fake xkmsd: `init` records its argv and SO PIN and writes the admin
# credential into --data-dir; a serve writes its bootstrap TLS certificate into
# the config's datastore path, as the real daemon does on start, then records
# whether it saw the PIN.
cat >"$WORK/xkmsd" <<'EOF'
#!/bin/bash
if [ "$1" = init ]; then
	echo "init $* pin=${XKMS_SO_PIN:-unset}" >>"$STUB_LOG"
	[ "${STUB_INIT_RC:-0}" -eq 0 ] || { echo "init: stub failure" >&2; exit "$STUB_INIT_RC"; }
	while [ $# -gt 0 ]; do
		[ "$1" = --data-dir ] && dir=$2
		shift
	done
	mkdir -p "$dir" && : >"$dir/admin-cert.pem"
	exit 0
fi
storage=$(awk '/^datastore:/ { d = 1 } d && $1 == "path:" { print $2; exit }' "$2")
mkdir -p "$storage/unified-tls" && : >"$storage/unified-tls/cert.pem"
echo "serve $* pin=${XKMS_SO_PIN:-unset}" >>"$STUB_SERVE_LOG"
EOF

# The fake curl serves a sealed barrier, whose /health refuses until the
# unseal; the unseal POST answers 204 and creates the socket, as the real
# daemon does once its barrier opens. As
# socket-probe.sh's curl --unix-socket it connects to a socket file once it
# has refused STUB_PROBE_DOWN_FOR probes.
cat >"$FAKEBIN/curl" <<'EOF'
#!/bin/bash
method=GET out="" data="" url="" sock=""
while [ $# -gt 0 ]; do
	case "$1" in
	-X) method=$2; shift ;;
	-o) out=$2; shift ;;
	-d) data=$2; shift ;;
	--unix-socket) sock=$2; shift ;;
	-w | -H | --cacert | --max-time) shift ;;
	-*) ;;
	*) url=$1 ;;
	esac
	shift
done
if [ -n "$sock" ]; then
	n=$(cat "$STUB_PROBE_COUNT" 2>/dev/null || echo 0)
	echo $((n + 1)) >"$STUB_PROBE_COUNT"
	if [ ! -S "$sock" ] || [ "$n" -lt "${STUB_PROBE_DOWN_FOR:-0}" ]; then
		echo "* Immediate connect fail for $sock: Connection refused" >&2
		echo "num_connects=0"
		exit 7
	fi
	echo "num_connects=1"
	exit 0
fi
echo "curl $method $url $data" >>"$STUB_LOG"
case "$url" in
*/health) [ -S "$STUB_SOCKET" ] || exit 22; exit 0 ;;
esac
if [ "$method" = GET ]; then
	printf '%s' "$STUB_STATUS"
	exit 0
fi
python3 -I -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$STUB_SOCKET"
[ -n "$out" ] && [ "$out" != /dev/null ] && : >"$out"
printf '204'
EOF

# nc must never probe: the runner's AppArmor profile for nc.openbsd refuses
# the socket (DS-3769). A call lands in the log the cases check.
printf '#!/bin/sh\necho "nc $*" >>"$STUB_LOG"\nexit 1\n' >"$FAKEBIN/nc"
printf '#!/bin/sh\nexit "${STUB_GETENT_RC:-2}"\n' >"$FAKEBIN/getent"
# sleep returns at once, except while the backgrounded fake daemon has not yet
# started: the opener polls for the certificate it writes.
printf '#!/bin/sh\n[ -e "$STUB_SERVE_LOG" ] || /bin/sleep 0.05\nexit 0\n' >"$FAKEBIN/sleep"
chmod +x "$FAKEBIN"/* "$WORK/xkmsd"

# run CASE [ENV=VALUE...] runs the script in a fresh case directory and sets
# $out, $rc, $calls and $dir.
run() {
	dir="$WORK/$1"
	shift
	mkdir -p "$dir/run"
	: >"$dir/calls"
	out=$(env "$@" PATH="$FAKEBIN:$PATH" STUB_LOG="$dir/calls" STUB_SERVE_LOG="$dir/serve" \
		STUB_XKMSD="$WORK/xkmsd" STUB_SOCKET="$dir/run/xkms.sock" STUB_PROBE_COUNT="$dir/probe-count" \
		STUB_STATUS="$SEALED" XKMS_TEST_DATA_DIR="$dir/data" XKMS_TEST_LOG="$dir/xkmsd.log" \
		XKMS_TEST_BIN="$dir/bin/xkmsd" XKMS_TEST_SO_PIN="$PIN" XKMS_TEST_REST_PORT=18999 \
		XKMS_SOCKET_WAIT=5 bash "$SCRIPT" "$dir/run/xkms.sock" 2>&1)
	rc=$?
	calls=$(cat "$dir/calls")
}

# served waits for the backgrounded fake daemon to record its start.
served() {
	local _
	for _ in $(seq 1 50); do
		[ -s "$1/serve" ] && break
		command sleep 0.1
	done
	cat "$1/serve" 2>/dev/null
}

bind_socket() {
	python3 -I -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$1"
}

section "no compose server: init, start without the PIN, unseal through open-server-barrier.sh"
run fallback XKMS_SO_PIN=inherited-pin
eq "exit 0" 0 "$rc"
has "the socket is ready" "is ready" "$out"
config=$(cat "$WORK/fallback/data/xkmsd.yaml")
lacks "the config carries no passphrase" "passphrase:" "$config"
lacks "the config carries no SO PIN" "$PIN" "$config"
has "the datastore is the storage dir" "datastore:
  engine: file
  path: $WORK/fallback/data/storage" "$config"
has "the sealed window listens on the loopback port" 'host: "localhost"
  rest_port: 18999' "$config"
has "init writes into the storage dir with the PIN in its environment" \
	"init init --config $WORK/fallback/data/xkmsd.yaml --data-dir $WORK/fallback/data/storage --hostname localhost --admin-factor mtls pin=$PIN" "$calls"
has "the opener unseals the loopback window with the PIN" \
	"curl POST https://localhost:18999/v1/barrier/unseal {\"secret\":\"$PIN_B64\"}" "$calls"
eq "the daemon runs without the PIN" "serve -config $WORK/fallback/data/xkmsd.yaml pin=unset" "$(served "$WORK/fallback")"

section "an initialized data directory is not initialized again"
mkdir -p "$WORK/again/data/storage"
: >"$WORK/again/data/storage/admin-cert.pem"
run again
eq "exit 0" 0 "$rc"
lacks "no init" "init init" "$calls"
has "the barrier is still unsealed" "curl POST https://localhost:18999/v1/barrier/unseal" "$calls"

section "a failed init stops before the daemon starts"
run initfail STUB_INIT_RC=1
eq "exit 1" 1 "$rc"
has "the failure is named" "xkmsd init failed" "$out"
has "init's own output follows" "init: stub failure" "$out"
lacks "no unseal" "curl POST" "$calls"
eq "no daemon" "" "$(cat "$WORK/initfail/serve" 2>/dev/null)"

section "a live socket is left alone"
mkdir -p "$WORK/live/run"
bind_socket "$WORK/live/run/xkms.sock"
run live
eq "exit 0" 0 "$rc"
has "it says so" "already served; leaving it alone" "$out"
eq "nothing built or started" "" "$calls"
eq "one curl probe decided it" 1 "$(cat "$WORK/live/probe-count")"

section "a compose server whose socket comes up late is waited for"
mkdir -p "$WORK/late/run"
bind_socket "$WORK/late/run/xkms.sock"
run late STUB_GETENT_RC=0 STUB_PROBE_DOWN_FOR=3
eq "exit 0" 0 "$rc"
has "it waits for the compose server" "xkms-server is running; waiting" "$out"
eq "nothing built or started" "" "$calls"
[ -S "$WORK/late/run/xkms.sock" ] && ok "the socket is kept" || no "the socket is kept" "a socket" "none"

section "a compose server whose socket never answers fails without replacing it"
mkdir -p "$WORK/dead/run"
bind_socket "$WORK/dead/run/xkms.sock"
run dead STUB_GETENT_RC=0 STUB_PROBE_DOWN_FOR=1000
eq "exit 1" 1 "$rc"
has "the failure is named" "accepts no connection; not replacing its socket" "$out"
has "the probe's own error follows" "Connection refused" "$out"
eq "nothing built or started" "" "$calls"
[ -S "$WORK/dead/run/xkms.sock" ] && ok "the socket is kept" || no "the socket is kept" "a socket" "none"

printf '\npassed %d, failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
