#!/bin/sh
#
# secure-analyzer.sh -- build go-qrdb's pkg/secure/analyzer singlechecker and
# sweep it, as `go vet -vettool=...`, over every Go module in this tree under
# every tag combination the Makefile already declares for testing that
# module. Called by `make secure-analyzer`; `make secure-analyzer-selftest`
# uses --build directly (see secure-analyzer-selftest.sh).
#
#   secure-analyzer.sh --build <abs-out>   build the tool at <abs-out>
#   secure-analyzer.sh --sweep             build + sweep + report
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
set -eu

ROOT="${SECURE_ANALYZER_ROOT:-.}"
GO="${GO:-go}"
TOOL_PKG=github.com/jeremyhahn/go-qrdb/pkg/secure/analyzer/cmd/secure-analyzer
ALLOWLIST="${SECURE_ANALYZER_ALLOWLIST:-$ROOT/scripts/secure-analyzer-allowlist.txt}"

# The module/tags matrix. One "module tags" pair per rung; tags is "-" for no
# -tags flag, otherwise a value `go vet -tags` accepts as-is (space or
# comma separated -- both work, see cmd/go/internal/work). This is DATA the
# Makefile authors, not this script: SECURE_ANALYZER_RUNGS, so a module's
# declared build tags are named exactly once (LINT_TAGS_xkey, TEST_TAGS) and
# do not drift into a second copy here.
RUNGS="${SECURE_ANALYZER_RUNGS:-}"

die() { printf '%s\n' "$@" >&2; exit 1; }

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

case "${1:---sweep}" in
--build)
	build_tool "${2:-}"
	exit 0
	;;
--sweep)
	;;
*)
	die "usage: secure-analyzer.sh [--build <abs-out> | --sweep]" ;;
esac

[ -n "$RUNGS" ] || die "secure-analyzer: SECURE_ANALYZER_RUNGS is empty; make must pass it"
[ -f "$ALLOWLIST" ] || die "secure-analyzer: allowlist not found at $ALLOWLIST"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM
: >"$WORK/hits"

TOOL="$WORK/secure-analyzer"
build_tool "$TOOL"

fails=0
rungs_run=0

# allowed prints the reason for KEY (repo-relative path:line) if KEY is a
# non-comment, non-blank line in the allowlist, or nothing if it is not.
allowed_reason() {
	awk -F'\t' -v k="$1" '
		/^[[:space:]]*#/ { next }
		NF < 2 { next }
		$1 == k { print $2; found=1; exit }
		END { if (!found) exit 1 }
	' "$ALLOWLIST"
}

# run_rung sweeps one module under one tag set. $1 = module dir ("." for the
# root), $2 = tags ("-" for none).
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

	while IFS= read -r line; do
		[ -n "$line" ] || continue
		if ! printf '%s\n' "$line" | grep -Eq '^[^:]+\.go:[0-9]+:[0-9]+: '; then
			# Not a diagnostic line (a build failure, a tool-start failure, a
			# panic) -- never suppressible, always a hard failure.
			fails=$((fails + 1))
			echo "  FAIL (not a securecheck diagnostic): $line"
			continue
		fi
		key=$(printf '%s\n' "$line" | grep -Eo '^[^:]+:[0-9]+')
		fullkey="${prefix}${key}"
		if reason=$(allowed_reason "$fullkey"); then
			echo "$fullkey" >>"$WORK/hits"
			echo "  ALLOWED $fullkey -- $reason"
		else
			fails=$((fails + 1))
			echo "  FAIL $fullkey: $line"
		fi
	done <"$out"
}

# check_stale fails on any allowlist entry that scored zero hits across the
# WHOLE sweep -- an exemption nothing matched is either already fixed (drop
# it) or was never reachable under any declared tag set (drop it or the
# reasoning that added it is wrong).
check_stale() {
	while IFS= read -r entry; do
		case "$entry" in
		''|'#'*) continue ;;
		esac
		key=$(printf '%s\n' "$entry" | cut -f1)
		[ -n "$key" ] || continue
		if ! grep -qxF "$key" "$WORK/hits" 2>/dev/null; then
			fails=$((fails + 1))
			echo "  FAIL: stale allowlist entry never matched by the sweep: $key"
		fi
	done <"$ALLOWLIST"
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

echo "secure-analyzer: clean -- $rungs_run rung(s), $(awk '!/^[[:space:]]*#/ && NF>=2' "$ALLOWLIST" | wc -l | tr -d ' ') allowlist entries all still needed"
