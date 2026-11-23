#!/usr/bin/env bash
# Tests for scripts/touched-features.sh (Tenant rulings 1170/1171): the
# test/integration/<feature> directories whose `make integration-test-<feature>`
# a diff requires, read from the tree and `go list`, or ALL when a change is
# outside every feature. Needs git and go; no network.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/scripts/touched-features.sh"
# shellcheck source=test/scripts/touched-lib.sh
. "$ROOT/test/scripts/touched-lib.sh"

run() { (cd "$REPO" && bash "$SCRIPT" "$@"); }
two() { printf '%s\n%s' "$1" "$2"; }

FA=$(commit_file test/integration/alpha/alpha_test.go '// alpha')
PA=$(commit_file pkg/a/a.go '// a')
PC=$(commit_file pkg/c/c.go '// c')
MK=$(commit_file Makefile '# make')
CM=$(commit_file test/integration/common/common.go '// common')
PD=$(commit_file pkg/d/d.go '// d')
put docs/guide.md '# guide'
put .changelog/unreleased/added-x.md '- x'
printf 'more\n' >>"$REPO/README.md"
DOC=$(commit_all docs)
RN=$(move_file test/integration/beta/extra_test.go test/integration/alpha/extra_test.go)

echo "touched-features.sh"
[ -x "$SCRIPT" ] && ok "the script is executable" || no "the script is executable"
eq "a feature-only diff prints that feature" "alpha" "$(run "$BASE" "$FA")"
eq "a package a feature imports transitively prints that feature" "alpha" "$(run "$FA" "$PA")"
eq "a package a second feature imports prints that feature" "beta" "$(run "$PA" "$PC")"
eq "a two-feature diff prints both, sorted" "$(two alpha beta)" "$(run "$BASE" "$PC")"
eq "a Makefile change prints ALL" "ALL" "$(run "$PC" "$MK")"
eq "a Makefile change among feature changes prints only ALL" "ALL" "$(run "$BASE" "$MK")"
eq "a test/integration/common change prints ALL" "ALL" "$(run "$MK" "$CM")"
eq "a package no feature reaches prints ALL" "ALL" "$(run "$CM" "$PD")"
eq "a docs-only change prints nothing" "" "$(run "$PD" "$DOC")"
eq "an empty diff prints nothing" "" "$(run "$DOC" "$DOC")"
eq "a rename between features prints both sides" "$(two alpha beta)" "$(run "$DOC" "$RN")"

# The integration-test-% recipe's full tag set, += lines included.
G=$(commit_file pkg/g/g.go '// g')
eq "a package only tag-gated feature tests import prints that feature" "gamma" "$(run "$RN" "$G")"
# A binary the suite builds and runs counts with its package deps.
T=$(commit_file pkg/t/t.go '// t')
eq "a dep of a binary the suite's own files build prints that feature" "delta" "$(run "$G" "$T")"
CT=$(commit_file cmd/tool/main.go '// tool')
eq "the binary the suite's own files build prints that feature" "delta" "$(run "$T" "$CT")"
S=$(commit_file pkg/s/s.go '// s')
eq "a dep of a binary the feature's recipe builds prints that feature" "eps" "$(run "$CT" "$S")"
U=$(commit_file pkg/u/u.go '// u')
eq "a dep of a nested-module binary the recipe builds prints that feature" "zeta" "$(run "$S" "$U")"
# Each explicit suite's graph under its own recipe's tags.
K=$(commit_file pkg/k/k.go '// k')
eq "a package a suite imports under its explicit rule's extra tag prints that suite" "$(two alpha kappa)" "$(run "$U" "$K")"
L=$(commit_file pkg/l/l.go '// l')
eq "a suite whose tests no recipe's tags build makes any package change ALL" "ALL" "$(run "$K" "$L")"

OUT=$(run "$BASE" no-such-revision 2>&1)
RC=$?
eq "a bad revision exits 2" "2" "$RC"
case "$OUT" in
ALL | alpha* | beta*) no "a bad revision prints no feature: [$OUT]" ;;
*) ok "a bad revision prints no feature" ;;
esac
run "$BASE" >/dev/null 2>&1
eq "a missing argument exits 2" "2" "$?"

finish
