#!/usr/bin/env bash
#
# check-test-helpers.sh — fail when production code depends on a test-only
# helper package.
#
# A test-only helper is a go-xkms package with a path segment ending in
# "test" (pkcs11test, tpm2test, xkmstest, test/...) or named mocks, testutil
# or testing. Helpers may import each other and any _test.go file may import
# them; a production package may not, because its binary would then link the
# helper (and package testing with it).
#
# For each module directory given, every non-helper package of the module is
# a production root. `go list -deps` walks their closure, and every non-helper
# package in it that imports a helper directly is reported as
# "<importer> -> <helper>". Build tags come from GOFLAGS, so
# `GOFLAGS=-tags=a,b` checks a tagged build.
#
# Usage: scripts/check-test-helpers.sh [MODULE_DIR...]
#   MODULE_DIR defaults to the repository's three modules: ., sdk/go, xkey.
#   test/scripts/check-test-helpers.test.sh runs it against scratch modules.
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
