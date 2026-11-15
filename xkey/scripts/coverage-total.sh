#!/usr/bin/env bash
# coverage-total.sh <profile>: prints the aggregate coverage percentage
# (without the % sign) of a Go coverage profile.
#
# It runs `$GO tool cover -func=<profile>` (GO defaults to go), keeps all of
# its output, and fails when the tool exits non-zero or prints no `total:`
# row. The tool can print function rows and then fail, so the last line is
# not a total unless it starts with `total:`.
set -u

if [ "$#" -ne 1 ]; then
	echo "usage: $0 <coverage-profile>" >&2
	exit 2
fi

go_cmd="${GO:-go}"
out="$("$go_cmd" tool cover -func="$1" 2>&1)"
status=$?
if [ "$status" -ne 0 ]; then
	printf '%s\n' "$out" >&2
	echo "coverage-total: go tool cover exited $status" >&2
	exit 1
fi

total=""
while IFS= read -r line; do
	case "$line" in
	total:*) total="$line" ;;
	esac
done <<< "$out"

if [ -z "$total" ]; then
	echo "coverage-total: go tool cover printed no total: row" >&2
	exit 1
fi

pct="${total##*[[:space:]]}"
pct="${pct%\%}"
case "$pct" in
'' | *[!0-9.]* | *.*.*)
	echo "coverage-total: malformed total row: $total" >&2
	exit 1
	;;
esac
printf '%s\n' "$pct"
