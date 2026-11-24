#!/bin/sh
# disk-usage.sh LABEL: print the size of the Lint job's Go module, build and golangci-lint caches and the free space beside them.

set -eu

if [ $# -ne 1 ] || [ -z "$1" ]; then
	echo "usage: $0 LABEL" >&2
	exit 2
fi

modcache="$(go env GOMODCACHE 2>/dev/null || true)"
buildcache="$(go env GOCACHE 2>/dev/null || true)"
# golangci-lint's own default: os.UserCacheDir()/golangci-lint.
lintcache="${GOLANGCI_LINT_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/golangci-lint}"

size() {
	if [ -n "$1" ] && [ -d "$1" ]; then
		du -sh -- "$1" 2>/dev/null | cut -f1 || echo "?"
	else
		echo "absent"
	fi
}

echo "disk usage $1:"
printf '  %-14s %8s  %s\n' GOMODCACHE "$(size "$modcache")" "$modcache"
printf '  %-14s %8s  %s\n' GOCACHE "$(size "$buildcache")" "$buildcache"
printf '  %-14s %8s  %s\n' golangci-lint "$(size "$lintcache")" "$lintcache"
printf '  %-14s %8s\n' free "$(df -Ph -- "$HOME" 2>/dev/null | tail -n 1 | tr -s ' ' | cut -d' ' -f4 || echo "?")"
