#!/usr/bin/env bash
# Tests for scripts/touched-packages.sh (Tenant rulings 1170/1171): the
# repo-relative package directories whose unit tests a diff requires (each
# changed package plus its direct importers in the root module), the input of
# `make test-pkg PKG=<dir>`. Needs git and go; no network.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/scripts/touched-packages.sh"
# shellcheck source=test/scripts/touched-lib.sh
. "$ROOT/test/scripts/touched-lib.sh"

run() { (cd "$REPO" && bash "$SCRIPT" "$@"); }

PA=$(commit_file pkg/a/a.go '// a')
PC=$(commit_file pkg/c/c.go '// c')
TD=$(commit_file pkg/c/testdata/in.json '{}')
put docs/guide.md '# guide'
put .changelog/unreleased/added-x.md '- x'
printf 'more\n' >>"$REPO/README.md"
DOC=$(commit_all docs)
RN=$(move_file pkg/a/extra.go pkg/e/extra.go)

echo "touched-packages.sh"
[ -x "$SCRIPT" ] && ok "the script is executable" || no "the script is executable"
eq "a changed package prints itself and its direct importer" "$(printf 'pkg/a\npkg/b')" "$(run "$BASE" "$PA")"
eq "a package without importers prints only itself" "pkg/c" "$(run "$PA" "$PC")"
eq "a testdata file prints the package that holds it" "pkg/c" "$(run "$PC" "$TD")"
eq "a docs-only change prints nothing" "" "$(run "$TD" "$DOC")"
eq "an empty diff prints nothing" "" "$(run "$DOC" "$DOC")"
eq "a rename prints both sides and the source's importer" "$(printf 'pkg/a\npkg/b\npkg/e')" "$(run "$DOC" "$RN")"

OUT=$(run "$BASE" no-such-revision 2>&1)
RC=$?
eq "a bad revision exits 2" "2" "$RC"
case "$OUT" in
pkg/*) no "a bad revision prints no package: [$OUT]" ;;
*) ok "a bad revision prints no package" ;;
esac
run "$BASE" >/dev/null 2>&1
eq "a missing argument exits 2" "2" "$?"

finish
