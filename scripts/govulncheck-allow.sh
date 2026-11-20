#!/usr/bin/env bash
# govulncheck-allow.sh: run govulncheck and fail on any reached vulnerability
# that the checked-in allowlist does not cover.
#
# govulncheck has no ignore flag, so this gate runs it with -format json and
# reads the OSV ids of the Symbol Results (findings whose trace reaches a
# function). It fails when:
#   - a reached id is not in the allowlist;
#   - an allowlist entry has passed its expiry date (UTC);
#   - an allowlist entry is no longer reached (remove stale entries);
#   - an allowlist line is malformed, or govulncheck itself fails.
#
# Allowlist (.govulncheck-allow at the repository root): one entry per line,
#   <OSV id> <expiry YYYY-MM-DD> <tracking issue URL>
# Blank lines and lines starting with # are ignored. An entry holds through
# its expiry day.
#
# Usage: scripts/govulncheck-allow.sh [govulncheck flags] [packages]
#   (default packages: ./...)
# Environment:
#   GOVULNCHECK_BIN        govulncheck binary (default: govulncheck on PATH,
#                          else $HOME/go/bin/govulncheck)
#   GOVULNCHECK_ALLOW_FILE allowlist path (default: <repo>/.govulncheck-allow)
#   GOVULNCHECK_TODAY      today's date YYYY-MM-DD (default: UTC today; tests)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
allow_file="${GOVULNCHECK_ALLOW_FILE:-$root/.govulncheck-allow}"
today="${GOVULNCHECK_TODAY:-$(date -u +%F)}"
bin="${GOVULNCHECK_BIN:-$(command -v govulncheck 2>/dev/null || echo "$HOME/go/bin/govulncheck")}"

die() { echo "govulncheck-allow: $*" >&2; exit 1; }

command -v jq >/dev/null 2>&1 || die "jq is required to read govulncheck JSON"
[ -x "$bin" ] || command -v "$bin" >/dev/null 2>&1 || die "govulncheck not found ($bin)"
[[ "$today" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die "GOVULNCHECK_TODAY '$today' is not YYYY-MM-DD"
[ -f "$allow_file" ] || die "allowlist $allow_file not found"

# Read the allowlist.
declare -A expiry=() issue=()
lineno=0
while IFS= read -r line || [ -n "$line" ]; do
	lineno=$((lineno + 1))
	line="${line%%$'\r'}"
	[[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
	read -r id date url extra <<<"$line"
	if [ -z "${url:-}" ] || [ -n "${extra:-}" ] ||
		! [[ "$id" =~ ^[A-Z]+-[0-9]{4}-[0-9]+$ ]] ||
		! [[ "$date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] ||
		! [[ "$url" =~ ^https:// ]]; then
		die "$allow_file:$lineno: malformed entry (want '<OSV id> <YYYY-MM-DD> <issue URL>'): $line"
	fi
	[ -z "${expiry[$id]:-}" ] || die "$allow_file:$lineno: duplicate entry $id"
	expiry[$id]="$date"
	issue[$id]="$url"
done <"$allow_file"

[ "$#" -gt 0 ] || set -- ./...

scan="$(mktemp)"
trap 'rm -f "$scan"' EXIT
"$bin" -format json "$@" >"$scan" || die "govulncheck failed (exit $?)"

# Symbol Results: the first trace frame names a function.
reached="$(jq -r 'select(.finding != null and (.finding.trace[0].function // "") != "") | .finding.osv' "$scan" | sort -u)" ||
	die "cannot parse govulncheck JSON output"

status=0
declare -A seen=()
for id in $reached; do
	seen[$id]=1
	if [ -z "${expiry[$id]:-}" ]; then
		echo "govulncheck-allow: $id is reached and not allowlisted (https://pkg.go.dev/vuln/$id)" >&2
		status=1
	fi
done
for id in $(printf '%s\n' "${!expiry[@]}" | sort); do
	if [[ "$today" > "${expiry[$id]}" ]]; then
		echo "govulncheck-allow: $id expired on ${expiry[$id]} (${issue[$id]}); fix it or renew the entry" >&2
		status=1
	elif [ -z "${seen[$id]:-}" ]; then
		echo "govulncheck-allow: $id is allowlisted but no longer reached; remove it from $(basename "$allow_file") (${issue[$id]})" >&2
		status=1
	else
		echo "govulncheck-allow: allowlisted $id until ${expiry[$id]} (${issue[$id]})"
	fi
done

if [ "$status" -ne 0 ]; then
	echo "govulncheck-allow: FAIL" >&2
	exit 1
fi
echo "govulncheck-allow: no reached vulnerability outside the allowlist"
