#!/usr/bin/env bash
#
# Unit tests for the pure functions in scripts/release-alpha.sh.
#
# Scope is deliberate: only the functions that are a function of their
# arguments are tested here, because only those can be tested without cutting a
# release. The parts that touch git -- branch and clean-tree preconditions,
# tagging, signature confirmation, the atomic push -- are exercised by
# `--dry-run` and by cutting a real release, not simulated. A harness that
# fakes those seams is go-xkms#211, not this file.
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
RELEASE_ALPHA_LIB=1 . "$ROOT/scripts/release-alpha.sh"
set +e

PASS=0
FAIL=0

ok() {
	PASS=$((PASS + 1))
	printf '  ok   %s\n' "$1"
}

no() {
	FAIL=$((FAIL + 1))
	printf '  FAIL %s\n    want: %s\n    got:  %s\n' "$1" "$2" "$3" >&2
}

eq() { # eq <name> <want> <got>
	[ "$2" = "$3" ] && ok "$1" || no "$1" "$2" "$3"
}

true_() { # true_ <name> <command...>
	local name=$1
	shift
	"$@" && ok "$name" || no "$name" "true" "false"
}

false_() { # false_ <name> <command...>
	local name=$1
	shift
	"$@" && no "$name" "false" "true" || ok "$name"
}

section() { printf '\n%s\n' "$1"; }

# --- next_version: defect 1, PATCH-only bumping -----------------------------

section "next_version"
eq "patch bumps PATCH" "v0.8.1-alpha" "$(next_version v0.8.0-alpha patch)"
eq "minor bumps MINOR and zeroes PATCH" "v0.9.0-alpha" "$(next_version v0.8.4-alpha minor)"
eq "major bumps MAJOR and zeroes both" "v1.0.0-alpha" "$(next_version v0.8.4-alpha major)"
# The carry case the old awk recipe got right by accident and the string
# handling can get wrong: 9 -> 10, not 9 -> 91 or a truncated 1.
eq "patch carries 9 -> 10" "v0.7.10-alpha" "$(next_version v0.7.9-alpha patch)"
eq "minor carries 9 -> 10" "v0.10.0-alpha" "$(next_version v0.9.4-alpha minor)"
eq "patch carries 19 -> 20" "v0.7.20-alpha" "$(next_version v0.7.19-alpha patch)"
# A leading zero must not be read as octal, which would make 08 a syntax error
# rather than eight.
eq "an 08 field is decimal, not octal" "v0.9.0-alpha" "$(next_version v0.8.9-alpha minor)"
eq "a v-less input is accepted" "v0.8.1-alpha" "$(next_version 0.8.0-alpha patch)"
false_ "an unknown bump level is refused" next_version v0.8.0-alpha sideways

# --- version_gt -------------------------------------------------------------

section "version_gt"
true_  "PATCH greater" version_gt v0.8.1-alpha v0.8.0-alpha
false_ "PATCH lesser" version_gt v0.8.0-alpha v0.8.1-alpha
false_ "equal is not greater" version_gt v0.8.0-alpha v0.8.0-alpha
true_  "MINOR outranks PATCH" version_gt v0.9.0-alpha v0.8.99-alpha
true_  "MAJOR outranks MINOR" version_gt v1.0.0-alpha v0.99.0-alpha
# Lexical comparison says v0.9.10 < v0.9.9; numeric comparison is the point.
true_  "0.9.10 is greater than 0.9.9" version_gt v0.9.10-alpha v0.9.9-alpha
false_ "0.9.9 is not greater than 0.9.10" version_gt v0.9.9-alpha v0.9.10-alpha

# --- is_alpha_semver --------------------------------------------------------

section "is_alpha_semver"
true_  "a well-formed alpha version" is_alpha_semver v0.9.1-alpha
false_ "a bare glob match is not a version" is_alpha_semver vfoo
false_ "a two-field version" is_alpha_semver v0.9-alpha
false_ "a date-shaped tag" is_alpha_semver v2026-08-21
false_ "a non-alpha release" is_alpha_semver v0.9.1
false_ "a different prerelease" is_alpha_semver v0.9.1-beta
false_ "trailing text after alpha" is_alpha_semver v0.9.1-alpha.1
false_ "the empty string" is_alpha_semver ""

# --- max_version ------------------------------------------------------------

section "max_version"
eq "picks the greatest" "v0.10.0-alpha" "$(printf 'v0.9.1-alpha\nv0.10.0-alpha\nv0.9.9-alpha\n' | max_version)"
eq "discards malformed tags rather than coercing them" "v0.9.1-alpha" \
	"$(printf 'v0.9.1-alpha\nvfoo\nv2026-08-21\n' | max_version)"
eq "no well-formed input yields nothing" "" "$(printf 'vfoo\n\n' | max_version)"
eq "empty input yields nothing" "" "$(printf '' | max_version)"

# --- changelog_has_heading: the anchored preflight --------------------------

section "changelog_has_heading"
CL=$(mktemp)
printf '# Changelog\n\n## [0.9.2-alpha]\n\n### Fixed\n' >"$CL"
true_  "an anchored heading is found" changelog_has_heading "$CL" 0.9.2-alpha
false_ "a version with no section is refused" changelog_has_heading "$CL" 0.9.3-alpha
# The workflow's matcher is anchored (grep -qE "^## \[$VERSION\]"). An
# unanchored preflight accepts this file and the workflow then rejects the tag
# -- after it has been published and become permanent.
printf '# Changelog\n\nsee ## [0.9.2-alpha] below\n' >"$CL"
false_ "an embedded heading does not satisfy the preflight" changelog_has_heading "$CL" 0.9.2-alpha
false_ "a missing CHANGELOG is refused" changelog_has_heading "$CL.absent" 0.9.2-alpha
rm -f "$CL"

# --- pin_version: require pins vs replace directives ------------------------

section "pin_version"
FIX=$(mktemp -d)
cat >"$FIX/go.mod" <<'EOF'
module github.com/jeremyhahn/go-xkms/xkey

replace (
	github.com/jeremyhahn/go-xkms => ../
	github.com/jeremyhahn/go-xkms/sdk/go => ../sdk/go
)

require (
	github.com/jeremyhahn/go-xkms v0.9.1-alpha
	github.com/jeremyhahn/go-xkms/sdk/go v0.9.1-alpha // indirect
)
EOF
# xkey/go.mod really does put its replace block first, and a replace entry is
# indented and begins with the module path exactly like a require entry -- so a
# matcher anchored on the path alone reads "=>" as the version and refuses
# every release.
eq "a replace block above the require is skipped" "v0.9.1-alpha" \
	"$(pin_version "$FIX/go.mod" github.com/jeremyhahn/go-xkms)"
eq "an indirect pin keeps its version" "v0.9.1-alpha" \
	"$(pin_version "$FIX/go.mod" github.com/jeremyhahn/go-xkms/sdk/go)"
# The bare path must not swallow the /sdk/go and /xkey lines beneath it.
eq "an absent module has no pin" "" \
	"$(pin_version "$FIX/go.mod" github.com/jeremyhahn/go-xkms/xkey)"
eq "a missing file has no pin" "" "$(pin_version "$FIX/absent.mod" github.com/jeremyhahn/go-xkms)"

# --- rewrite_pin + require_pins_at over a declared edge set -----------------

section "rewrite_pin and require_pins_at"
PIN_EDGES=(
	"go.mod:github.com/jeremyhahn/go-xkms"
	"go.mod:github.com/jeremyhahn/go-xkms/sdk/go"
)
true_ "a consistent edge set validates at its version" \
	require_pins_at "$FIX" v0.9.1-alpha test

rewrite_pin "$FIX" go.mod github.com/jeremyhahn/go-xkms v0.9.1-alpha v0.9.2-alpha
eq "the rewritten pin moved" "v0.9.2-alpha" \
	"$(pin_version "$FIX/go.mod" github.com/jeremyhahn/go-xkms)"
eq "the sibling pin was NOT swallowed by the bare path" "v0.9.1-alpha" \
	"$(pin_version "$FIX/go.mod" github.com/jeremyhahn/go-xkms/sdk/go)"
false_ "a half-rewritten edge set is refused" \
	require_pins_at "$FIX" v0.9.2-alpha test 2>/dev/null

rewrite_pin "$FIX" go.mod github.com/jeremyhahn/go-xkms/sdk/go v0.9.1-alpha v0.9.2-alpha
true_ "the fully rewritten edge set validates" \
	require_pins_at "$FIX" v0.9.2-alpha test
true_ "the '// indirect' comment survived the rewrite" \
	grep -q 'sdk/go v0.9.2-alpha // indirect' "$FIX/go.mod"
true_ "the versionless replace directives were left alone" \
	grep -q 'github.com/jeremyhahn/go-xkms => \.\./' "$FIX/go.mod"

# A DELETED edge is the case a count-of-pins comparison fails open on: it is
# absent from the before total and the after total alike, so the two match.
sed -i '/go-xkms\/sdk\/go v0/d' "$FIX/go.mod"
false_ "a deleted reciprocal edge is refused, not silently skipped" \
	require_pins_at "$FIX" v0.9.2-alpha test 2>/dev/null
eq "the deleted edge is named as removed" "1" \
	"$(require_pins_at "$FIX" v0.9.2-alpha test 2>&1 >/dev/null | grep -c 'has no require pin')"

# A STALE edge is the other: still counted at neither version.
PIN_EDGES=("go.mod:github.com/jeremyhahn/go-xkms")
sed -i 's|go-xkms v0.9.2-alpha|go-xkms v0.9.1-alpha|' "$FIX/go.mod"
false_ "a stale reciprocal edge is refused" \
	require_pins_at "$FIX" v0.9.2-alpha test 2>/dev/null
eq "the stale edge is named with both versions" "1" \
	"$(require_pins_at "$FIX" v0.9.2-alpha test 2>&1 >/dev/null | grep -c 'is at v0.9.1-alpha, want v0.9.2-alpha')"

PIN_EDGES=("absent/go.mod:github.com/jeremyhahn/go-xkms")
false_ "a declared edge whose file is gone is refused" \
	require_pins_at "$FIX" v0.9.2-alpha test 2>/dev/null

rm -rf "$FIX"

# --- escape_dots ------------------------------------------------------------

section "escape_dots"
eq "dots are escaped for a BRE" 'v0\.9\.1-alpha' "$(escape_dots v0.9.1-alpha)"
eq "a module path is escaped" 'github\.com/jeremyhahn/go-xkms' "$(escape_dots github.com/jeremyhahn/go-xkms)"

# --- the declared edge set matches the repository ---------------------------
#
# The edge set is declared rather than discovered, which is what makes it
# bounded -- and what makes it able to drift. This is the check that turns a
# new module, or a removed reciprocal require, into a failing test at the
# commit that introduces it rather than into a silently incomplete release.

section "the declared edge set covers the repository"
unset PIN_EDGES
RELEASE_ALPHA_LIB=1 . "$ROOT/scripts/release-alpha.sh"
set +e

DECLARED=$(printf '%s\n' "${PIN_EDGES[@]}" | sort)
ACTUAL=$(cd "$ROOT" && git ls-tree -r --name-only HEAD | grep 'go\.mod$' | while read -r f; do
	grep -oE '^[[:space:]]+github\.com/jeremyhahn/go-xkms(/[a-z/]+)?[[:space:]]+v[0-9]' "$ROOT/$f" |
		awk -v f="$f" '{print f ":" $1}'
done | sort)
eq "every reciprocal require in the repository is a declared edge" "$ACTUAL" "$DECLARED"

# RELEASE_FILES is what the release commit stages. A file that carries an edge
# but is not staged would be rewritten, validated, and then left out of the
# commit -- a release that passes every check and ships a stale pin.
DECLARED_FILES=$(printf '%s\n' "${PIN_EDGES[@]}" | cut -d: -f1 | sort -u)
STAGED_FILES=$(printf '%s\n' "${RELEASE_FILES[@]}" | grep -v '^VERSION$' | sort -u)
eq "every file carrying an edge is staged by the release commit" "$DECLARED_FILES" "$STAGED_FILES"
true_ "VERSION is staged by the release commit" \
	grep -qx VERSION <<<"$(printf '%s\n' "${RELEASE_FILES[@]}")"

VERSION_FILE=$(tr -d ' \t\n' <"$ROOT/VERSION")
true_ "the VERSION file holds a well-formed alpha version" is_alpha_semver "v$VERSION_FILE"
true_ "the repository's pins are all at the VERSION file's version" \
	require_pins_at "$ROOT" "v$VERSION_FILE" "the checked-out tree"

# ---------------------------------------------------------------------------


# --- changelog_entries_pending: the pipefail/SIGPIPE regression (go-xkms#388) --
CEP=$(mktemp -d)
mkdir -p "$CEP/none" "$CEP/readme" "$CEP/one" "$CEP/many"
printf 'r\n' > "$CEP/readme/README.md"
printf -- '- a\n' > "$CEP/one/fixed-a-1.md"
for i in 1 2 3 4 5; do printf -- '- e%s\n' "$i" > "$CEP/many/fixed-e$i.md"; done
printf 'r\n' > "$CEP/many/README.md"
if changelog_entries_pending "$CEP/missing"; then no "missing dir reported pending"; else ok "missing dir: not pending"; fi
if changelog_entries_pending "$CEP/none";    then no "empty dir reported pending";   else ok "empty dir: not pending"; fi
if changelog_entries_pending "$CEP/readme";  then no "README-only reported pending"; else ok "README only: not pending"; fi
if changelog_entries_pending "$CEP/one";     then ok "one entry: pending";            else no "one entry: not detected"; fi
if changelog_entries_pending "$CEP/many";    then ok "five entries under pipefail: pending"; else no "five entries: assembler would be SKIPPED (SIGPIPE 141)"; fi
rm -rf "$CEP"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
