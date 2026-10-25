#!/usr/bin/env bash
#
# go-test-each.sh — run `go test` once per package, each run with its own
# GOTMPDIR that is removed as soon as the run ends, and merge the per-package
# coverage profiles into one.
#
# Usage:
#	scripts/go-test-each.sh [--jobs N] --coverprofile FILE [GO TEST FLAG...] -- PKG...
#
# --jobs (default 2) is how many packages run at once. Each package's output is
# printed whole when its run ends, so packages never interleave. The exit code
# is the first failing package's, in argument order, or 0. $GO names the go
# binary (default `go`).
#
# Why this exists (m1261). A single multi-package `go test` keeps every package
# archive it compiles in its WORK directory (under GOTMPDIR) until the whole
# invocation exits. On a cold build cache test-go's WORK reached 3.5 GB of
# _pkg_.a copies, on top of the build cache that already holds the same
# archives, and the Unit Tests job filled a runner's root disk. One invocation
# per package releases its WORK directory after each package, so the peak is
# one package's dependency graph instead of the whole tree's.
#
# The merged profile holds the same blocks as a multi-package run's: a package
# without tests contributes no blocks either way.
set -euo pipefail

usage() {
	echo "usage: go-test-each.sh [--jobs N] --coverprofile FILE [GO TEST FLAG...] -- PKG..." >&2
	exit 2
}

jobs=2
profile=""
flags=()

while [ $# -gt 0 ]; do
	case "$1" in
	--jobs)
		[ $# -ge 2 ] || usage
		jobs="$2"
		shift 2
		;;
	--coverprofile)
		[ $# -ge 2 ] || usage
		profile="$2"
		shift 2
		;;
	--)
		shift
		break
		;;
	*)
		flags+=("$1")
		shift
		;;
	esac
done

[ -n "$profile" ] || usage
[ $# -ge 1 ] || usage
case "$jobs" in '' | *[!0-9]*)
	echo "go-test-each.sh: --jobs must be a positive integer, got '$jobs'" >&2
	exit 2
	;;
esac
[ "$jobs" -ge 1 ] || { echo "go-test-each.sh: --jobs must be >= 1, got '$jobs'" >&2; exit 2; }

pkgs=("$@")
go_bin=${GO:-go}

# Short path: tests bind unix sockets under their temp dirs, and a socket path
# is capped at 108 bytes.
work=$(mktemp -d "${TMPDIR:-/tmp}/gte.XXXXXX")
trap 'rm -rf "$work"' EXIT

# run_one I PKG — test one package in $work/I, keeping only its log, profile
# and exit code, then print the log under a lock so outputs never interleave.
run_one() {
	local dir="$work/$1"
	mkdir -p "$dir/tmp"
	local rc=0
	GOTMPDIR="$dir/tmp" "$go_bin" test "${flags[@]}" -coverprofile="$dir/cover.out" "$2" > "$dir/log" 2>&1 || rc=$?
	rm -rf "$dir/tmp"
	echo "$rc" > "$dir/rc"
	flock "$work/lock" cat "$dir/log"
}

running=0
for i in "${!pkgs[@]}"; do
	if [ "$running" -ge "$jobs" ]; then
		wait -n
		running=$((running - 1))
	fi
	run_one "$i" "${pkgs[$i]}" &
	running=$((running + 1))
done
wait

mkdir -p "$(dirname "$profile")"
: > "$profile"
status=0
for i in "${!pkgs[@]}"; do
	dir="$work/$i"
	rc=$(cat "$dir/rc")
	if [ "$rc" -ne 0 ] && [ "$status" -eq 0 ]; then
		status=$rc
	fi
	[ -s "$dir/cover.out" ] || continue
	if [ -s "$profile" ]; then
		tail -n +2 "$dir/cover.out" >> "$profile"
	else
		cat "$dir/cover.out" > "$profile"
	fi
done
exit "$status"
