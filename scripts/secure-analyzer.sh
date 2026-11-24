#!/bin/sh
#
# secure-analyzer.sh: run go-qrdb's pkg/secure/analyzer over every Go module in this tree under each declared tag set.
set -eu

# ROOT is canonicalized to an absolute path once, here, rather than left as
# the default "." (or whatever relative value SECURE_ANALYZER_ROOT carries):
# every "$ROOT/$module" built below is handed to
# scripts/secure-analyzer-symbol as both its -root and (joined with a
# diagnostic's own relative file) the file to read, and that tool's
# containment check (resolveFile) treats a relative FILE as relative to
# root -- a relative ROOT would make "$ROOT/$module/$relfile" relative to
# the PROCESS's cwd instead, which is a different base, and got silently
# double-joined onto -root before this line existed.
ROOT="${SECURE_ANALYZER_ROOT:-.}"
ROOT=$(cd "$ROOT" && pwd) || {
	printf 'secure-analyzer: SECURE_ANALYZER_ROOT %s does not resolve to a directory\n' "$ROOT" >&2
	exit 1
}
GO="${GO:-go}"
TOOL_PKG=github.com/jeremyhahn/go-qrdb/pkg/secure/analyzer/cmd/secure-analyzer
SYMBOL_PKG=./scripts/secure-analyzer-symbol
ALLOWLIST="${SECURE_ANALYZER_ALLOWLIST:-$ROOT/scripts/secure-analyzer-allowlist.txt}"

# The module/tags matrix. One "module tags" pair per rung; tags is "-" for no
# -tags flag, otherwise a value `go vet -tags` accepts as-is (space or
# comma separated -- both work, see cmd/go/internal/work). This is DATA the
# Makefile authors, not this script: SECURE_ANALYZER_RUNGS, so a module's
# declared build tags are named exactly once (LINT_TAGS_xkey, TEST_TAGS) and
# do not drift into a second copy here.
RUNGS="${SECURE_ANALYZER_RUNGS:-}"

die() { printf '%s\n' "$@" >&2; exit 1; }

# rule_for, symbol_for, allowed_reason, process_diagnostics and check_stale
# live in secure-analyzer-key.sh, shared with secure-analyzer-selftest.sh so
# the selftest's keying regression case exercises this exact matching logic
# rather than a second copy of it (go-xkms#607).
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) ||
	die "secure-analyzer: could not resolve this script's own directory"
# shellcheck source=scripts/secure-analyzer-key.sh
. "$SCRIPT_DIR/secure-analyzer-key.sh"

# build_tool compiles the singlechecker to an ABSOLUTE path.
#
# Absolute because the sweep cd's into each module before invoking go vet, so
# a relative -vettool path resolves against the wrong directory for three of
# the four modules -- and go vet reports that as a tool it could not start,
# not as a clean sweep, which is at least loud. Still not worth relying on
# the difference.
build_tool() {
	[ -n "${1:-}" ] || die "secure-analyzer: --build needs an output path"
	case "$1" in
	/*) ;;
	*) die "secure-analyzer: output path must be absolute, got [$1]" ;;
	esac
	(cd "$ROOT" && $GO build -o "$1" "$TOOL_PKG") ||
		die "secure-analyzer: the analyzer itself does not build." \
			"  Nothing downstream of this is a measurement of the tree."
	[ -x "$1" ] || die "secure-analyzer: build reported success but produced no executable at $1"
}

# build_symtool compiles scripts/secure-analyzer-symbol (see the KEYING
# comment above) to an ABSOLUTE path, for the same reason build_tool's does:
# the sweep cd's into each module before it is needed.
build_symtool() {
	[ -n "${1:-}" ] || die "secure-analyzer: build_symtool needs an output path"
	case "$1" in
	/*) ;;
	*) die "secure-analyzer: output path must be absolute, got [$1]" ;;
	esac
	(cd "$ROOT" && $GO build -o "$1" "$SYMBOL_PKG") ||
		die "secure-analyzer: scripts/secure-analyzer-symbol does not build." \
			"  Rule 2 and rule 3 findings cannot be keyed without it."
	[ -x "$1" ] || die "secure-analyzer: symtool build reported success but produced no executable at $1"
}

case "${1:---sweep}" in
--build)
	build_tool "${2:-}"
	exit 0
	;;
--build-symtool)
	build_symtool "${2:-}"
	exit 0
	;;
--sweep)
	;;
*)
	die "usage: secure-analyzer.sh [--build <abs-out> | --build-symtool <abs-out> | --sweep]" ;;
esac

[ -n "$RUNGS" ] || die "secure-analyzer: SECURE_ANALYZER_RUNGS is empty; make must pass it"
[ -f "$ALLOWLIST" ] || die "secure-analyzer: allowlist not found at $ALLOWLIST"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM
: >"$WORK/hits"

TOOL="$WORK/secure-analyzer"
build_tool "$TOOL"

SYMTOOL="$WORK/secure-analyzer-symbol"
build_symtool "$SYMTOOL"

fails=0
rungs_run=0

# run_rung sweeps one module under one tag set. $1 = module dir ("." for the
# root), $2 = tags ("-" for none). Classification, keying and allowlist
# matching happen in process_diagnostics (secure-analyzer-key.sh), which
# also appends every allowed finding's key to "$WORK/hits" for check_stale.
run_rung() {
	module="$1"
	tags="$2"
	prefix=""
	[ "$module" = "." ] || prefix="$module/"

	tagdesc=""
	[ "$tags" = "-" ] || tagdesc=" [tags: $tags]"
	echo "secure-analyzer: ($module)$tagdesc"

	pkgcount=$(
		if [ "$tags" = "-" ]; then
			(cd "$ROOT/$module" && $GO list ./... 2>/dev/null)
		else
			(cd "$ROOT/$module" && $GO list -tags "$tags" ./... 2>/dev/null)
		fi | grep -c .
	) || pkgcount=0
	if [ "$pkgcount" -eq 0 ]; then
		fails=$((fails + 1))
		echo "  FAIL: matched no packages in $module under [$tags] -- vet would look at nothing"
		return
	fi

	out="$WORK/rung.out"
	if [ "$tags" = "-" ]; then
		(cd "$ROOT/$module" && $GO vet -vettool="$TOOL" ./...) >"$out" 2>&1 || true
	else
		(cd "$ROOT/$module" && $GO vet -vettool="$TOOL" -tags "$tags" ./...) >"$out" 2>&1 || true
	fi

	rungs_run=$((rungs_run + 1))
	[ -s "$out" ] || { echo "  clean -- $pkgcount packages"; return; }

	process_diagnostics "$out" "$prefix" "$ROOT/$module"
}

echo "secure-analyzer: securecheck rules 1-7, every module, every declared combination"
set -- $RUNGS
while [ $# -ge 2 ]; do
	run_rung "$1" "$2"
	shift 2
done

check_stale

if [ "$rungs_run" -eq 0 ]; then
	die "secure-analyzer: swept zero rungs -- SECURE_ANALYZER_RUNGS did not parse into any module/tags pair"
fi

if [ "$fails" -ne 0 ]; then
	die "" "secure-analyzer: $fails unresolved finding(s) across $rungs_run rung(s)." \
		"  Rule 1 is absolute. Rule 2 is absolute outside" \\
		"  scripts/secure-analyzer-allowlist.txt's one named exemption class. Rule 3 is scoped by" \\
		"  pkg/secure/analyzer/scope.go's four clauses -- read it before assuming a" \
		"  finding is a false positive, and before adding an allowlist entry for" \
		"  anything other than a pre-existing finding or the named rule-2 class." \
		"  Rules 4-5 (string conversion, unwiped copy-out) are never" \
		"  allowlisted and carry no //secure: directive in this repository: fix the" \
		"  site with WithBytes / secure.CopyOut and a wipe, or keep the value as []byte."
fi

echo "secure-analyzer: clean -- $rungs_run rung(s), $(awk -F'\t' '!/^[[:space:]]*#/ && NF>=4' "$ALLOWLIST" | wc -l | tr -d ' ') allowlist entries all still needed"
