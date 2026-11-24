#!/usr/bin/env bash
# gitea-host.sh: print the module forge as host:port, or nothing when modules resolve publicly.
set -euo pipefail

if [ -n "${GITEA_HOST:-}" ]; then
	printf '%s\n' "$GITEA_HOST"
	exit 0
fi

root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
env_file="$root/build/docker/devcontainer/.env"
if [ -f "$env_file" ]; then
	from_env=$(sed -n 's/^GITEA_HOST=//p' "$env_file" | tail -n 1)
	if [ -n "$from_env" ]; then
		printf '%s\n' "$from_env"
		exit 0
	fi
fi

origin=$(git -C "$root" remote get-url origin 2>/dev/null || true)
http_port="${GITEA_HTTP_PORT:-3001}"

case "$origin" in
	*github.com*|"")
		exit 0
		;;
	ssh://*)
		# ssh://[user@]host[:port]/path
		hostport=${origin#ssh://}
		hostport=${hostport#*@}
		hostport=${hostport%%/*}
		host=${hostport%%:*}
		printf '%s:%s\n' "$host" "$http_port"
		;;
	http://*|https://*)
		# http[s]://[user@]host[:port]/path -- the HTTP API is what the
		# origin already speaks, so host and port are taken as written.
		hostport=${origin#*://}
		hostport=${hostport#*@}
		hostport=${hostport%%/*}
		printf '%s\n' "$hostport"
		;;
	*@*:*)
		# scp-like user@host:path
		host=${origin#*@}
		host=${host%%:*}
		printf '%s:%s\n' "$host" "$http_port"
		;;
	*)
		exit 0
		;;
esac
