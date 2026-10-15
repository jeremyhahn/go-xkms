#!/bin/sh
# disk-usage.sh LABEL -- print the size of the three caches the Lint job
# fills inside its container (go-xkms#1553): the module cache (GOMODCACHE),
# the build cache (GOCACHE) and golangci-lint's analysis cache, plus the free
# space left on the filesystem holding them. The Lint job calls it after
# `make vet` and, through `make lint LINT_CI=1`, after every golangci-lint
# pass, so each run's log carries the figures the job's disk use is sized by.
#
# Measurement only: a cache that does not exist yet prints "absent", and
# nothing du or go reports can fail the step being measured. The one failure
# is a missing label (exit 2).

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
