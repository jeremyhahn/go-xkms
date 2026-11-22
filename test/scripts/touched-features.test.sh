#!/usr/bin/env bash
# Tests for scripts/touched-features.sh (Tenant ruling 1170): the features a
# diff touches, from a features.tsv, or ALL when a changed file belongs to no
# feature. Builds a throwaway git repository; needs only git.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/scripts/touched-features.sh"

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; }
eq() { # eq <name> <want> <got>
	if [ "$2" = "$3" ]; then ok "$1"; else no "$1: want [$2] got [$3]"; fi
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
REPO="$WORK/repo"
TSV="$WORK/features.tsv"
printf 'feature\tpaths\tunit\tintegration\n' >"$TSV"
printf 'alpha\tdocs/alpha/ pkg/alpha/\t./pkg/alpha/...\t-\n' >>"$TSV"
printf 'beta\tdocs/beta/ pkg/beta/ pkg/shared/x.go\t-\tintegration-test-beta\n' >>"$TSV"
printf 'gamma\tpkg/gamma/ pkg/shared/x.go\t-\t-\n' >>"$TSV"

g() { git -C "$REPO" -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false "$@"; }
commit() { # commit <file> <msg>: write file, commit, print the commit id
	mkdir -p "$REPO/$(dirname "$1")"
	echo "$2" >>"$REPO/$1"
	g add -A >/dev/null && g commit -q -m "$2" && g rev-parse HEAD
}
run() { (cd "$REPO" && FEATURES_TSV="$TSV" bash "$SCRIPT" "$@"); }

git init -q "$REPO"
BASE=$(commit README.md base)
A=$(commit pkg/alpha/a.go alpha)
B=$(commit docs/beta/README.md beta)
M=$(commit Makefile make)
P=$(commit pkg/alphabet/z.go alphabet)
S=$(commit pkg/shared/x.go shared)

echo "touched-features.sh"
eq "a feature-only diff prints that feature" "alpha" "$(run "$BASE" "$A")"
eq "a two-feature diff prints both, sorted" "$(printf 'alpha\nbeta')" "$(run "$BASE" "$B")"
eq "a Makefile change prints ALL" "ALL" "$(run "$B" "$M")"
eq "a change outside every row among feature changes prints only ALL" "ALL" "$(run "$BASE" "$M")"
eq "a directory prefix does not match a longer sibling name" "ALL" "$(run "$M" "$P")"
eq "a file path shared by two features prints both" "$(printf 'beta\ngamma')" "$(run "$P" "$S")"
eq "an empty diff prints nothing" "" "$(run "$A" "$A")"

OUT=$(run "$BASE" no-such-revision 2>&1)
RC=$?
eq "a bad revision exits 2" "2" "$RC"
case "$OUT" in
ALL | alpha*) no "a bad revision prints no feature: [$OUT]" ;;
*) ok "a bad revision prints no feature" ;;
esac

OUT=$(run "$BASE" 2>&1)
RC=$?
eq "a missing argument exits 2" "2" "$RC"

printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
exit $?
