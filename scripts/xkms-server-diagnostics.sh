#!/usr/bin/env bash
# xkms-server-diagnostics.sh: report why the compose xkms-server is not serving the integration suites' Unix socket.
set -u

SOCKET="${1:-/var/run/xkms/xkms.sock}"
COMPOSE="${DOCKER_COMPOSE:-docker compose}"
STATE_FORMAT='status={{.State.Status}} exit_code={{.State.ExitCode}} oom_killed={{.State.OOMKilled}} restart_count={{.RestartCount}} started_at={{.State.StartedAt}} finished_at={{.State.FinishedAt}} apparmor={{.AppArmorProfile}} selinux={{.ProcessLabel}} privileged={{.HostConfig.Privileged}}'

# The socket, its directory and the caller's LSM label, as seen by whoever
# runs it; $1 is the socket path.
# shellcheck disable=SC2016
SEE_SOCKET='stat -c "%A %u:%g inode=%i %y %n" "$(dirname "$1")" "$1" 2>&1
printf "lsm label: %s\n" "$(cat /proc/self/attr/current 2>/dev/null || echo none)"'

# SEE_SOCKET, the caller's identity and the connect(2) the suites make, by
# socket-probe.sh, whose text is $2: the devcontainer runs it without needing
# to know where the repository is mounted.
# shellcheck disable=SC2016
PROBE_SOCKET="id
${SEE_SOCKET}"'
if out=$(sh -c "$2" socket-probe "$1" 2>&1); then echo "socket-probe: connected"; else echo "socket-probe: failed: ${out:-no output}"; fi'
PROBE_SCRIPT=$(<"$(dirname "${BASH_SOURCE[0]}")/socket-probe.sh") ||
	PROBE_SCRIPT='echo "socket-probe.sh is missing beside xkms-server-diagnostics.sh" >&2; exit 1'

# The Makefile's compose command starts with a COMPOSE_PROJECT_NAME=...
# assignment, which env applies before running docker.
compose() {
	# shellcheck disable=SC2086
	env $COMPOSE "$@"
}

indent() {
	sed 's/^/    /'
}

section() {
	printf -- '--- xkms-server diagnostics: %s\n' "$1"
}

section "container state"
cid=$(compose ps -aq xkms-server 2>/dev/null)
if [ -n "$cid" ]; then
	docker inspect -f "$STATE_FORMAT" "$cid" 2>&1 | indent
else
	echo "no xkms-server container" | indent
fi

section "$SOCKET as xkms-server sees it"
compose exec -T xkms-server sh -c "$SEE_SOCKET" sh "$SOCKET" 2>&1 | indent

section "$SOCKET from the devcontainer as the suite's user"
compose exec -T devcontainer sh -c "$PROBE_SOCKET" sh "$SOCKET" "$PROBE_SCRIPT" 2>&1 | indent

section "$SOCKET from the devcontainer as root"
compose exec -T -u root devcontainer sh -c "$PROBE_SOCKET" sh "$SOCKET" "$PROBE_SCRIPT" 2>&1 | indent

section "AppArmor and SELinux denials in the kernel log"
# The denying profile is named on its own line: a host profile can attach to a
# tool inside the container by its path, as nc.openbsd's did to the probe's
# nc, and then the tool, not the server, is what is refused.
# shellcheck disable=SC2016
compose exec -T -u root devcontainer sh -c \
	'denials=$(dmesg 2>&1 | grep -Ei "apparmor=\"DENIED\"|avc: +denied" | tail -n 20); echo "${denials:-none}"
profiles=$(printf "%s\n" "$denials" | grep -Eo "profile=\"[^\"]+\"" | cut -d\" -f2 | sort -u | paste -sd " " -)
[ -z "$profiles" ] || echo "denied by AppArmor profile: $profiles"' \
	2>&1 | indent

section "last 200 lines of the xkms-server log"
compose logs --no-color --tail 200 xkms-server 2>&1 | indent

exit 0
