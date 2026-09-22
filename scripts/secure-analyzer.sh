#!/bin/sh
#
# secure-analyzer.sh -- build go-qrdb's pkg/secure/analyzer singlechecker and
# sweep it, as `go vet -vettool=...`, over every Go module in this tree under
# every tag combination the Makefile already declares for testing that
# module. Called by `make secure-analyzer`; `make secure-analyzer-selftest`
# uses --build and --build-symtool directly (see secure-analyzer-selftest.sh).
#
#   secure-analyzer.sh --build <abs-out>           build the analyzer at <abs-out>
#   secure-analyzer.sh --build-symtool <abs-out>   build the symbol helper at <abs-out>
#   secure-analyzer.sh --sweep                     build both + sweep + report
#
# WHY THIS EXISTS (go-xkms#549)
#
# go-qrdb's pkg/secure/analyzer is a complete, unit-tested go/analysis pass
# enforcing three rules on sensitive-material handling (raw memguard imports,
# ssh.ParsePrivateKey, string/[]byte holder fields) -- but an analyzer
# enforces nothing where its make target does not run, and nothing in
# go-qrdb reaches into this repository. Before this script go-xkms's
# compliance with those three rules was unmeasured, not known-good.
#
# TWO TRAPS THIS SCRIPT EXISTS TO AVOID, both measured while sizing #549:
#
#   - `go vet ./...` DOES NOT CROSS A MODULE BOUNDARY. This repository has
#     four go.mod files (., sdk/go, xkey, web/desktop); a single invocation
#     from the root reaches the root module only.
#   - A single build-tag combination answers about the files THAT
#     combination compiles and says nothing about the others -- the same
#     blindness LINT_TAGS_xkey exists to remove from `make vet`/`make lint`.
#     The root module is therefore swept both untagged (matching `make vet`)
#     and under TEST_TAGS (matching what `make test` actually compiles).
#
# THE ALLOWLIST is not a baseline. It exempts a bounded, named set of
# findings the Makefile passes as SECURE_ANALYZER_ALLOWLIST, each carrying a
# reason in the file itself (scripts/secure-analyzer-allowlist.txt). Every
# other finding fails the sweep. An allowlist entry that stops matching
# ANYTHING across the whole sweep is stale and fails the sweep too (see
# check_stale) -- silence is not evidence the exemption is still needed.
#
# KEYING (go-xkms#607): an entry keys on path + rule + the finding's own
# symbol text, NOT path:line. A path:line key breaks on any edit that shifts
# the line -- happened twice on 2026-09-21 (fido2.go 208->207, mock_extended
# after go-xkms#154) -- with no signal beyond a red Lint on main days later.
# The symbol is: rule 1, the forbidden import path (constant, and already in
# the diagnostic message -- no parsing needed beyond the message itself);
# rule 2, the call expression's own source text; rule 3, "<Struct>.<Field>".
# Rule 2 and 3's symbols are not in the diagnostic message (rule 2's message
# is the same fixed string for every call site; rule 3's never names the
# struct), so both are read back out of the source at the reported
# file:line:col by scripts/secure-analyzer-symbol, a small go/ast-based
# helper built alongside the analyzer itself (see symbol_for below).
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

echo "secure-analyzer: securecheck rules 1-3, every module, every declared combination"
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
		"  Rules 1 and 2 are absolute outside scripts/secure-analyzer-allowlist.txt's" \
		"  two named exemption classes. Rule 3 is scoped by" \
		"  pkg/secure/analyzer/scope.go's four clauses -- read it before assuming a" \
		"  finding is a false positive, and before adding an allowlist entry for" \
		"  anything other than a pre-existing finding or one of the two named classes."
fi

echo "secure-analyzer: clean -- $rungs_run rung(s), $(awk -F'\t' '!/^[[:space:]]*#/ && NF>=4' "$ALLOWLIST" | wc -l | tr -d ' ') allowlist entries all still needed"
