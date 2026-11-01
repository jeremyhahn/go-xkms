#!/usr/bin/env bash
#
# Tests for scripts/xkms-server-diagnostics.sh (DS-3769).
#
# The helper runs on the host when a readiness step gives up, so it must say
# why the socket is not served without ever printing the PINs the compose
# environment carries, and must never turn a diagnosed failure into a second
# one. These tests run it against a fake `docker` on PATH that logs every call
# and runs each `compose exec` command locally, with fake `id`, `curl` and
# `dmesg` (and an `nc` that must never run) standing in for the containers. No Docker, no network.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/scripts/xkms-server-diagnostics.sh"
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

PIN="stub-so-pin-1234"
SOCKET="$WORK/run/xkms.sock"
mkdir -p "$WORK/run"

# The fake docker. `inspect` prints the -f format it was given, and without -f
# it prints the container's environment, PIN included, as docker does.
# `compose ... ps` prints $STUB_CID; `compose ... logs` prints a log line;
# `compose ... exec [-T] [-u USER] SERVICE CMD...` runs CMD here with
# STUB_EXEC_USER set to USER (or "suite"). $STUB_DOCKER_DOWN fails every call.
FAKEBIN="$WORK/bin"
mkdir -p "$FAKEBIN"
cat >"$FAKEBIN/docker" <<'EOF'
#!/bin/bash
echo "docker $*" >>"$STUB_LOG"
if [ -n "${STUB_DOCKER_DOWN:-}" ]; then
	echo "Cannot connect to the Docker daemon" >&2
	exit 1
fi
if [ "$1" = inspect ]; then
	if [ "$2" = -f ]; then
		echo "rendered: $3"
	else
		echo "\"Env\": [\"XKMS_SO_PIN=$STUB_PIN\"]"
	fi
	exit 0
fi
shift
while [ $# -gt 0 ]; do
	case "$1" in ps | exec | logs) break ;; esac
	shift
done
sub=$1
shift
case "$sub" in
ps) [ -z "$STUB_CID" ] || echo "$STUB_CID" ;;
logs) echo "stub xkms-server log line" ;;
exec)
	user=suite
	while [ $# -gt 0 ]; do
		case "$1" in
		-T) ;;
		-u) user=$2; shift ;;
		*) break ;;
		esac
		shift
	done
	shift
	STUB_EXEC_USER=$user exec "$@"
	;;
esac
EOF
cat >"$FAKEBIN/id" <<'EOF'
#!/bin/sh
echo "uid=stub($STUB_EXEC_USER)"
EOF
# The fake curl answers socket-probe.sh: root connects, the suite's user is
# refused at connect(2). The fake nc logs a call, which the probe must never
# make (DS-3769).
cat >"$FAKEBIN/curl" <<'EOF'
#!/bin/sh
while [ $# -gt 0 ]; do
	[ "$1" = --unix-socket ] && sock=$2
	shift
done
if [ "$STUB_EXEC_USER" = root ]; then
	echo "num_connects=1"
	exit 0
fi
echo "* Immediate connect fail for $sock: Permission denied" >&2
echo "curl: (7) Failed to connect to localhost port 80 after 0 ms: Could not connect to server" >&2
echo "num_connects=0"
exit 7
EOF
cat >"$FAKEBIN/nc" <<'EOF'
#!/bin/sh
echo "nc-ran $*" >>"$STUB_LOG"
exit 1
EOF
cat >"$FAKEBIN/dmesg" <<'EOF'
#!/bin/sh
echo '[1.0] eth0: link up'
echo '[2.0] audit: type=1400 apparmor="DENIED" operation="connect" class="file" info="Failed name lookup - disconnected path" error=-13 profile="nc.openbsd" name="run/xkms/xkms.sock"'
echo '[3.0] audit: type=1400 apparmor="DENIED" operation="connect" profile="docker-default"'
echo '[4.0] audit: type=1400 apparmor="DENIED" operation="capable" class="cap" profile="nc.openbsd" capname="dac_override"'
EOF
chmod +x "$FAKEBIN"/*

# run [ENV...] -- run the helper against $SOCKET. Sets out, rc, calls.
run() {
	: >"$WORK/calls"
	out=$(env PATH="$FAKEBIN:$PATH" STUB_LOG="$WORK/calls" STUB_PIN="$PIN" STUB_CID=c0ffee \
		DOCKER_COMPOSE="COMPOSE_PROJECT_NAME=stub docker compose -p stub" "$@" bash "$SCRIPT" "$SOCKET" 2>&1)
	rc=$?
	calls=$(cat "$WORK/calls")
}

section "a server refusing the suite's user is explained"
run
eq "exit 0" 0 "$rc"
has "it reports the container state" "rendered: status={{.State.Status}} exit_code={{.State.ExitCode}}" "$out"
has "it reports the restart count" "restart_count={{.RestartCount}}" "$out"
has "it reports the AppArmor profile" "apparmor={{.AppArmorProfile}}" "$out"
lacks "it never inspects the config" ".Config" "$calls"
lacks "it never prints the environment" "$PIN" "$out"
has "it asks xkms-server about the socket" "exec -T xkms-server sh -c" "$calls"
has "it runs the Makefile's compose command" "docker compose -p stub ps -aq xkms-server" "$calls"
has "it probes as the suite's user" "uid=stub(suite)" "$out"
has "it probes as root" "uid=stub(root)" "$out"
has "the suite's user is refused" "socket-probe: failed: * Immediate connect fail for $SOCKET: Permission denied" "$out"
has "root connects" "socket-probe: connected" "$out"
lacks "it never probes with nc" "nc-ran" "$calls"
has "it stats the socket's directory" "$WORK/run" "$out"
has "it prints the kernel's denial" 'apparmor="DENIED" operation="connect"' "$out"
lacks "it prints only denials from the kernel log" "eth0: link up" "$out"
has "it names each denying profile once" "denied by AppArmor profile: docker-default nc.openbsd" "$out"
has "it asks for the last 200 log lines" "logs --no-color --tail 200 xkms-server" "$calls"
has "it prints the server log" "    stub xkms-server log line" "$out"

section "no container is said so, without inspecting"
run STUB_CID=
eq "exit 0" 0 "$rc"
has "it says there is no container" "no xkms-server container" "$out"
lacks "it inspects nothing" "docker inspect" "$calls"
has "it still prints the server log" "stub xkms-server log line" "$out"

section "docker failing everywhere still exits 0"
run STUB_DOCKER_DOWN=1
eq "exit 0" 0 "$rc"
has "it carries docker's error" "Cannot connect to the Docker daemon" "$out"
has "it reaches the last section" "last 200 lines of the xkms-server log" "$out"

printf '\npassed %d, failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
