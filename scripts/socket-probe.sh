#!/bin/sh
# socket-probe.sh: connect to a Unix socket as the caller and report whether it succeeded.

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
