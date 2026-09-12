#!/usr/bin/env bash
# gitea-host.sh prints the in-house Gitea server as host:port of its HTTP
# API, or nothing when this checkout resolves modules publicly.
#
# Resolution order:
#   1. GITEA_HOST in the environment.
#   2. GITEA_HOST= in the gitignored .devcontainer/.env, beside GITEA_GO_TOKEN.
#   3. The repository's own origin remote, which in any real Gitea checkout
#      names the server. An SSH origin (ssh://git@host:2222/... or
#      git@host:...) maps its SSH port to the HTTP port (GITEA_HTTP_PORT,
#      default 3001); an HTTP(S) origin keeps host and port as written.
#
# A github.com origin with no override prints nothing and exits 0: that is
# the public resolution path (no insteadOf rewrite, modules from the proxy),
# not an error. Anything that needs the host and gets an empty string names
# GITEA_HOST in its failure.
set -euo pipefail

if [ -n "${GITEA_HOST:-}" ]; then
	printf '%s\n' "$GITEA_HOST"
	exit 0
fi

root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
env_file="$root/.devcontainer/.env"
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
