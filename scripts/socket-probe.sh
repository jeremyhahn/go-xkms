#!/bin/sh
# socket-probe.sh — connect(2) to a Unix socket as the caller and say whether
# the connect succeeded (DS-3769).
#
# Every readiness step and diagnostic that asks "can this user reach the
# socket" runs this one probe. It is curl --unix-socket, not nc -U: CI runner
# hosts ship an AppArmor profile for nc.openbsd that attaches to nc inside the
# devcontainer and refuses a connect to a socket on a volume it cannot name
# ("Failed name lookup - disconnected path"), so nc reported EACCES for a
# socket the suites reach. curl's num_connects counts the connections curl
# opened, so it proves the connect(2) whatever the TLS socket makes of the
# plaintext request that follows; the verbose trace carries connect(2)'s
# error when it fails.
#
# Usage:
#   socket-probe.sh SOCKET
# Environment:
#   XKMS_SOCKET_PROBE_TIMEOUT  seconds curl may spend on the probe (default 3)
#
# Exits 0 when the connect succeeded; otherwise 1, with the reason on stderr.

socket="${1:?usage: socket-probe.sh SOCKET}"

if ! command -v curl >/dev/null 2>&1; then
	echo "socket-probe: curl is not installed" >&2
	exit 1
fi

trace=$(curl -sSv -o /dev/null -w '\nnum_connects=%{num_connects}\n' \
	--max-time "${XKMS_SOCKET_PROBE_TIMEOUT:-3}" \
	--unix-socket "$socket" http://localhost/ 2>&1)
case "$trace" in
*"num_connects="[1-9]*) exit 0 ;;
esac

# connect(2)'s error, then curl's summary of it. curl 7.87 and later trace
# "Immediate connect fail for SOCKET: ERROR", earlier ones "connect to SOCKET
# port 0 failed: ERROR".
printf '%s\n' "$trace" | while IFS= read -r line; do
	case "$line" in
	*"connect fail"* | *"connect to "*" failed"* | curl:*) printf '%s\n' "$line" >&2 ;;
	esac
done
exit 1
