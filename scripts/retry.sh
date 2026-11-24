#!/usr/bin/env bash
#
# retry.sh: run a command a bounded number of times with linear backoff.
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
