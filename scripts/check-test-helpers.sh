#!/usr/bin/env bash
#
# check-test-helpers.sh: fail when production code depends on a test-only helper package.
set -uo pipefail

HELPER='^github\.com/jeremyhahn/go-xkms/(.*/)?([a-z0-9]*test|mocks|testutil|testing)(/|$)'

if [ "$#" -eq 0 ]; then
	root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
	set -- "$root" "$root/sdk/go" "$root/xkey"
fi

status=0
for mod in "$@"; do
	if ! pkgs=$(cd "$mod" && go list ./...); then
		echo "check-test-helpers: go list failed in $mod" >&2
		status=1
		continue
	fi
	roots=$(grep -Ev "$HELPER" <<<"$pkgs")
	[ -n "$roots" ] || continue

	# shellcheck disable=SC2086 # roots is a whitespace-separated package list
	if ! closure=$(cd "$mod" && go list -deps -f '{{.ImportPath}}{{range .Imports}} {{.}}{{end}}' $roots); then
		echo "check-test-helpers: go list -deps failed in $mod" >&2
		status=1
		continue
	fi

	leaks=""
	while read -r pkg imports; do
		[[ $pkg =~ $HELPER ]] && continue
		for imp in $imports; do
			[[ $imp =~ $HELPER ]] && leaks+="  $pkg -> $imp"$'\n'
		done
	done <<<"$closure"

	if [ -n "$leaks" ]; then
		printf 'check-test-helpers: production packages import test-only helpers (%s):\n%s' "$mod" "$leaks" >&2
		status=1
	fi
done
exit "$status"
