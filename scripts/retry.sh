#!/usr/bin/env bash
#
# retry.sh — run a command a bounded number of times with linear backoff,
# stopping at the first success.
#
# Usage:
#	scripts/retry.sh [--attempts N] [--backoff SECONDS] -- CMD [ARG...]
#
# Defaults: --attempts 3 --backoff 15.
#
# Why this exists (go-xkms#1026). release.yml's linux/arm64 legs (QEMU
# emulation) and its Docker image builds fail some fraction of the time on
# runner infrastructure -- the docker daemon hits `context deadline
# exceeded`, or setup-qemu's binfmt cache hits an ENOENT copy race -- not on
# the code being built. Three of the last seven release tags shipped an
# incomplete asset set for exactly this reason. This is a PLAIN bounded shell
# loop, not a third-party retry action: attempt N sleeps `N * BACKOFF`
# seconds before attempt N+1, and the wrapped command's stdout/stderr reach
# the caller unmodified on every attempt, so a genuine code failure still
# shows its real error, just three times.
#
# This does not distinguish an infrastructure failure from a code failure --
# it cannot, from outside the command -- so a broken build also retries and
# then fails after the last attempt. That costs 2 * BACKOFF seconds on a
# release run measured in tens of minutes, which is what release.yml's own
# 75-minute leg timeout already budgets for.
set -euo pipefail

usage() {
	echo "usage: retry.sh [--attempts N] [--backoff SECONDS] -- CMD [ARG...]" >&2
	exit 2
}

attempts=3
backoff=15

while [ $# -gt 0 ]; do
	case "$1" in
	--attempts)
		[ $# -ge 2 ] || usage
		attempts="$2"
		shift 2
		;;
	--backoff)
		[ $# -ge 2 ] || usage
		backoff="$2"
		shift 2
		;;
	--)
		shift
		break
		;;
	-h | --help)
		usage
		;;
	*)
		echo "retry.sh: unexpected argument: $1" >&2
		usage
		;;
	esac
done

[ $# -ge 1 ] || usage

case "$attempts" in '' | *[!0-9]*)
	echo "retry.sh: --attempts must be a positive integer, got '$attempts'" >&2
	exit 2
	;;
esac
[ "$attempts" -ge 1 ] || { echo "retry.sh: --attempts must be >= 1, got '$attempts'" >&2; exit 2; }

case "$backoff" in '' | *[!0-9]*)
	echo "retry.sh: --backoff must be a non-negative integer, got '$backoff'" >&2
	exit 2
	;;
esac

attempt=0
while [ "$attempt" -lt "$attempts" ]; do
	attempt=$((attempt + 1))
	echo "retry.sh: attempt ${attempt}/${attempts}: $*" >&2
	# rc MUST be captured in the else branch, not after `fi`: an `if` whose
	# condition is false and which has no matching command in an else clause
	# exits 0 by POSIX definition, so `rc=$?` placed after a bare `if/fi`
	# silently reads 0 on every failure (caught by retry.test.sh, which was
	# red against that shape before this comment existed).
	if "$@"; then
		exit 0
	else
		rc=$?
	fi
	if [ "$attempt" -ge "$attempts" ]; then
		echo "retry.sh: giving up after ${attempts} attempts (last exit ${rc}): $*" >&2
		exit "$rc"
	fi
	sleep_for=$((attempt * backoff))
	echo "retry.sh: attempt ${attempt} failed (exit ${rc}); retrying in ${sleep_for}s" >&2
	sleep "$sleep_for"
done
