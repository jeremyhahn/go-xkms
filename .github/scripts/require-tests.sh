#!/usr/bin/env bash
#
# Runs the named tests in a package, and fails when any of the names matches
# nothing.
#
# `go test -run` treats a selector that matches no test as success: it compiles
# the package, runs zero tests, prints ok and exits 0. Two of the nested-module
# gates in ci.yml are built out of such selectors — the ble-tagged peripheral
# lifecycle tests and the GUI teardown tests, both named individually because
# their packages hold pre-existing failures — so a rename or a deletion would
# have quietly turned each into a green job that tests nothing. A check that
# cannot fail is not a check.
#
# Every name is therefore asserted to exist before anything runs. Names are
# matched as anchored prefixes, the same way `go test -run` matches them, so
# naming a family (TestBLEPeripheral_Stop) covers its members.
#
# Usage: require-tests.sh <package> <build-tags|""> <test name>...

set -euo pipefail

if [ "$#" -lt 3 ]; then
	echo "usage: $0 <package> <build-tags|\"\"> <test name>..." >&2
	exit 2
fi

pkg=$1
shift
tags=$1
shift

tagflag=()
if [ -n "$tags" ]; then
	tagflag=(-tags "$tags")
fi

for name in "$@"; do
	# Captured rather than piped into grep: `grep -q` closes the pipe on its
	# first match, go test dies of SIGPIPE, and pipefail turns a successful
	# lookup into a failure.
	listed=$(go test "${tagflag[@]}" -list "^${name}" "$pkg")
	if ! printf '%s\n' "$listed" | grep -q "^${name}"; then
		echo "::error::no test matches ^${name} in ${pkg} (tags='${tags}')"
		echo "The gate's -run selector would match nothing, so the job would pass" >&2
		echo "having verified nothing. Fix the name, or drop it deliberately." >&2
		exit 1
	fi
done

selector=$(printf '%s|' "$@")
selector=${selector%|}

go test -race -v "${tagflag[@]}" "$pkg" -run "^(${selector})"
