#!/usr/bin/env bash
#
# Unit tests for scripts/release-alpha.sh: the pure functions directly, and
# the fetch/checkout/commit/push flow end to end against a throwaway fixture
# repository with its own bare "dev" remote (go-xkms#419/#211 rewrote this
# script to fetch and prepare a pull request rather than publish directly, so
# a fixture with no remote at all can no longer exercise it).
#
# scripts/release-tag.sh -- the tagging, signature confirmation and atomic
# push that used to live here -- has its own suite,
# test/scripts/release-tag.test.sh, which sources this file's pure functions
# the same way the script itself does.
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

# --- bump_level: the growth gate's trigger, derived rather than declared ----
#
# go-xkms#419's incident shipped nine new exported symbols with NO --bump flag
# at all, so the growth gate cannot gate on the flag being present -- it has
# to derive the same answer --bump would have declared, from the two versions
# alone.

section "bump_level"
eq "a patch-only difference" "patch" "$(bump_level v0.9.1-alpha v0.9.2-alpha)"
eq "a multi-patch jump is still patch" "patch" "$(bump_level v0.9.1-alpha v0.9.9-alpha)"
eq "a minor difference" "minor" "$(bump_level v0.9.4-alpha v0.10.0-alpha)"
eq "minor outranks a simultaneous patch difference" "minor" "$(bump_level v0.9.4-alpha v0.10.1-alpha)"
eq "a major difference" "major" "$(bump_level v0.9.4-alpha v1.0.0-alpha)"
eq "major outranks minor and patch together" "major" "$(bump_level v0.9.4-alpha v1.1.1-alpha)"

# --- remote_repo_path: the PR URL's path half --------------------------------
#
# Mirrors scripts/gitea-host.sh's own case structure over the HOST half of the
# same URL, deliberately: the two compose into one PR URL without either
# script guessing at the shape the other already handles.

section "remote_repo_path"
eq "an ssh:// remote" "jeremyhahn/go-xkms" \
	"$(remote_repo_path 'ssh://git@git.example.internal:2222/jeremyhahn/go-xkms.git')"
eq "an http remote" "jeremyhahn/go-xkms" \
	"$(remote_repo_path 'http://git.example.internal/jeremyhahn/go-xkms.git')"
eq "an scp-like remote" "jeremyhahn/go-xkms" \
	"$(remote_repo_path 'git@198.51.100.50:jeremyhahn/go-xkms.git')"
eq "an unrecognized shape yields nothing, not a guess" "" \
	"$(remote_repo_path '/media/local4tb/git/go-xkms.git')"
eq "the empty string yields nothing" "" "$(remote_repo_path '')"

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


# --- fetch/checkout/commit/push against a real tree (end to end) -----------
#
# go-xkms#419/#211 rewrote release-alpha.sh to fetch --remote/--branch and
# read VERSION, the pins and CHANGELOG.md from that fetched tip rather than
# from whatever is checked out locally, and to stop at a pushed branch
# instead of tagging and publishing. Every fixture below therefore carries
# its own bare "dev" remote: a repository with none can no longer exercise
# this script at all, which is itself part of what changed.
#
# Git runs against every fixture with the host's global and system config
# disabled, so the result is a property of the script rather than of
# whoever's machine runs the suite. The only network these tests reach is a
# bare repository under mktemp -d beside the fixture -- nothing external.

section "--dry-run against a real tree (end to end)"

FXROOT=$(mktemp -d)

fxgit() { # fxgit <repo> <args...>
	local r=$1
	shift
	GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git -C "$r" "$@"
}

fxmod() { # fxmod <repo> <path> <module> <required...>
	local r=$1 path=$2 self=$3 m
	shift 3
	mkdir -p "$r/$(dirname "$path")"
	{
		printf 'module %s\n\ngo 1.24\n\nrequire (\n' "$self"
		for m in "$@"; do printf '\t%s v0.1.0-alpha\n' "$m"; done
		printf ')\n'
	} >"$r/$path"
}

# mkbare creates a fresh bare repository under FXROOT and prints its path.
mkbare() {
	local b
	b=$(mktemp -d -p "$FXROOT")/bare.git
	GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git init -q --bare -b main "$b" >/dev/null
	printf '%s' "$b"
}

# mkfixture builds a throwaway repository at $1 carrying the shape the script
# demands -- VERSION, every declared pin edge, a CHANGELOG with an Unreleased
# heading, pending entries, copies of both scripts plus exportsurface (the
# growth gate shells out to `go build` on it) -- commits it, tags the commit
# v0.1.0-alpha (the baseline the growth gate's tests compare against), adds a
# bare "dev" remote and pushes main to it. Prints the bare remote's path.
mkfixture() {
	local r=$1 x=github.com/jeremyhahn/go-xkms bare
	mkdir -p "$r/scripts/exportsurface" "$r/.changelog/unreleased"
	printf '0.1.0-alpha\n' >"$r/VERSION"
	fxmod "$r" go.mod "$x" "$x/sdk/go" "$x/xkey"
	fxmod "$r" sdk/go/go.mod "$x/sdk/go" "$x" "$x/xkey"
	fxmod "$r" xkey/go.mod "$x/xkey" "$x" "$x/sdk/go"
	fxmod "$r" web/desktop/go.mod "$x/web/desktop" "$x" "$x/sdk/go" "$x/xkey"
	printf '# Changelog\n\n## [Unreleased]\n\n## [0.1.0-alpha] - 2026-01-01\n\n### Fixed\n\n- old entry\n' \
		>"$r/CHANGELOG.md"
	printf -- '- **thing** one ([#1](x))\n' >"$r/.changelog/unreleased/fixed-one-1.md"
	printf -- '- **thing** two ([#2](x))\n' >"$r/.changelog/unreleased/added-two-2.md"
	printf 'contributor notes\n' >"$r/.changelog/unreleased/README.md"
	cp "$ROOT/scripts/release-alpha.sh" "$ROOT/scripts/changelog-assemble.sh" "$r/scripts/"
	cp "$ROOT/scripts/exportsurface/main.go" "$r/scripts/exportsurface/main.go"
	fxgit "$r" init -q -b main
	fxgit "$r" add -A
	fxgit "$r" -c user.name=test -c user.email=test@example.invalid \
		-c commit.gpgsign=false commit -q -m "fixture"
	fxgit "$r" tag v0.1.0-alpha
	bare=$(mkbare)
	fxgit "$r" remote add dev "$bare"
	fxgit "$r" push -q dev main
	printf '%s' "$bare"
}

# fxmanifest is the tree-identity assertion: the index and worktree state git
# reports, plus a content hash of every file the changelog steps can touch. A
# deletion, a rewrite and a staging all change it. It deliberately does not
# look at refs or branches -- a fetch updating remote-tracking refs is not a
# working-tree mutation and must not fail this check.
fxmanifest() { # fxmanifest <repo>
	fxgit "$1" status --porcelain
	(cd "$1" && find CHANGELOG.md .changelog -type f -exec sha256sum {} + 2>&1 | LC_ALL=C sort)
}

fxrelease() { # fxrelease <repo> <args...>
	local r=$1
	shift
	(cd "$r" && GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
		bash scripts/release-alpha.sh "$@" 2>&1)
}

# The script reaches git through $GIT, which makes "a dry run writes nothing"
# answerable directly rather than only by its effects: every subcommand is
# recorded and the write verbs must not appear. A tree-identity check alone
# cannot see a write whose content happened to match. A dry run DOES read the
# network now (fetch, fetch --tags), which is the point of go-xkms#211 -- only
# the write verbs are forbidden.
cat >"$FXROOT/git-wrap" <<'WRAP'
#!/usr/bin/env bash
printf '%s\n' "${1:-}" >>"$GITLOG"
exec git "$@"
WRAP
chmod +x "$FXROOT/git-wrap"

FX="$FXROOT/dry"
mkfixture "$FX" >/dev/null
BEFORE=$(fxmanifest "$FX")
GITLOG="$FXROOT/git-calls"
: >"$GITLOG"
export GITLOG GIT="$FXROOT/git-wrap"
OUT=$(fxrelease "$FX" --version 0.2.0-alpha --bump minor --dry-run)
RC=$?
unset GIT
AFTER=$(fxmanifest "$FX")

eq "the dry run succeeds" "0" "$RC"
eq "the working tree is byte-identical after a dry run" "$BEFORE" "$AFTER"
eq "the checked-out branch is unchanged after a dry run" "main" "$(fxgit "$FX" symbolic-ref --short HEAD)"
eq "no local branch was created by a dry run" "" "$(fxgit "$FX" branch --list 'release/*')"
eq "no changelog entry was consumed" "2" \
	"$(find "$FX/.changelog/unreleased" -name '*.md' ! -name README.md | wc -l | tr -d ' ')"
eq "the index is empty after a dry run" "" "$(fxgit "$FX" status --porcelain)"
true_ "the git wrapper observed the dry run" test -s "$GITLOG"
eq "a dry run runs no git write subcommand" "" \
	"$(grep -xE 'add|commit|push|reset|checkout|stash|rm|mv' "$GITLOG")"
false_ "CHANGELOG.md gained no section on disk" \
	grep -q '## \[0.2.0-alpha\]' "$FX/CHANGELOG.md"
# The rehearsal is only worth running if it still shows the operator what the
# release would look like -- including the changelog, which is the part that
# used to be shown by mutating it.
true_ "the preview prints the pin diff" \
	grep -qE '^\+[[:space:]]*github\.com/jeremyhahn/go-xkms/sdk/go v0\.2\.0-alpha' <<<"$OUT"
true_ "the preview prints the assembled changelog section" grep -q '^+## \[0.2.0-alpha\]' <<<"$OUT"
true_ "the preview prints the assembled entry text" grep -q '^+- \*\*thing\*\* one' <<<"$OUT"
true_ "the preview names the entry files a real cut would consume" \
	grep -q 'would remove .changelog/unreleased/fixed-one-1.md' <<<"$OUT"
true_ "the preview names the release branch, not a tag" \
	grep -q 'push release/v0.2.0-alpha to dev' <<<"$OUT"
false_ "the preview never mentions tagging -- that is release-tag.sh's job now" \
	grep -q 'sdk/go/v0.2.0-alpha' <<<"$OUT"

# Error handling: a malformed entry name must fail the rehearsal, and must
# fail it without having consumed anything either. The bad entry is pushed to
# the fixture's own remote -- a fetch-based script cannot be tripped by an
# unpushed local commit it will never read.
FXBAD="$FXROOT/bad"
mkfixture "$FXBAD" >/dev/null
printf -- '- oops\n' >"$FXBAD/.changelog/unreleased/typo-section-3.md"
fxgit "$FXBAD" add -A
fxgit "$FXBAD" -c user.name=test -c user.email=test@example.invalid \
	-c commit.gpgsign=false commit -q -m "bad entry"
fxgit "$FXBAD" push -q dev main
BEFORE=$(fxmanifest "$FXBAD")
OUT=$(fxrelease "$FXBAD" --version 0.2.0-alpha --bump minor --dry-run)
RC=$?
eq "a malformed entry name fails the dry run" "1" "$RC"
true_ "the failure names the assembler" grep -q 'changelog-assemble failed' <<<"$OUT"
eq "a failed dry run is byte-identical too" "$BEFORE" "$(fxmanifest "$FXBAD")"

# --- prepare reads the fetched remote tip, never the local checkout --------
#
# The whole point of go-xkms#211's "fetch-and-assert": a local checkout that
# has never seen a version published upstream must still be unable to
# republish it, because every read comes from what was JUST fetched.

section "prepare reads the fetched remote tip, not a stale local checkout (go-xkms#211)"

FXSTALE="$FXROOT/stale"
mkfixture "$FXSTALE" >/dev/null
BARE=$(fxgit "$FXSTALE" remote get-url dev)
FXPUSHER="$FXROOT/pusher"
GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git clone -q "$BARE" "$FXPUSHER"
printf '0.1.5-alpha\n' >"$FXPUSHER/VERSION"
fxgit "$FXPUSHER" add -A
fxgit "$FXPUSHER" -c user.name=test -c user.email=test@example.invalid \
	-c commit.gpgsign=false commit -q -m "someone else's release"
fxgit "$FXPUSHER" push -q origin main

# $FXSTALE has never fetched the commit FXPUSHER just made. If prepare
# trusted the local checkout, it would validate 0.1.5-alpha against the STALE
# 0.1.0-alpha still on disk here and accept a version already superseded.
OUT=$(fxrelease "$FXSTALE" --version 0.1.5-alpha --dry-run)
RC=$?
eq "a version already published upstream is refused, though the local checkout has never seen it" \
	"1" "$RC"
true_ "the refusal compares against the just-fetched version, not the stale local one" \
	grep -q 'is not greater than the current version v0.1.5-alpha' <<<"$OUT"

# --- prepare refuses a release branch that already exists on the remote ----

section "prepare refuses a duplicate release branch (go-xkms#419)"

FXDUP="$FXROOT/dup"
mkfixture "$FXDUP" >/dev/null
fxgit "$FXDUP" push -q dev "HEAD:refs/heads/release/v0.1.1-alpha"
OUT=$(fxrelease "$FXDUP" --version 0.1.1-alpha --dry-run)
RC=$?
eq "a release branch already on the remote is refused" "1" "$RC"
true_ "the refusal names the branch" grep -q 'release/v0.1.1-alpha' <<<"$OUT"

# --- the exported-API growth gate (go-xkms#419/#421) ------------------------

section "the exported-API growth gate"

FXGROW="$FXROOT/growth"
mkfixture "$FXGROW" >/dev/null
mkdir -p "$FXGROW/pkg/foo"
printf 'package foo\n\nfunc Exported() string { return "x" }\n' >"$FXGROW/pkg/foo/foo.go"
fxgit "$FXGROW" add -A
fxgit "$FXGROW" -c user.name=test -c user.email=test@example.invalid \
	-c commit.gpgsign=false commit -q -m "add pkg/foo, unreleased"
fxgit "$FXGROW" push -q dev main

OUT=$(fxrelease "$FXGROW" --version 0.1.1-alpha --dry-run)
RC=$?
eq "an implied PATCH bump that grew the API is refused" "1" "$RC"
true_ "the refusal names the added symbol" grep -q '\.:pkg/foo\.Exported' <<<"$OUT"
true_ "the refusal suggests the fix" grep -q -- '--bump minor' <<<"$OUT"

OUT=$(fxrelease "$FXGROW" --version 0.2.0-alpha --bump minor --dry-run)
RC=$?
eq "the same growth is allowed under a MINOR bump" "0" "$RC"

OUT=$(fxrelease "$FXGROW" --version 0.1.1-alpha --bump patch --dry-run)
RC=$?
eq "an explicit --bump patch is refused exactly like an implied one" "1" "$RC"

# --- a real cut prepares a pull request branch, and stops (end to end) -----

section "a real cut prepares a pull request branch, and stops"

FXREAL="$FXROOT/real"
BARE=$(mkfixture "$FXREAL")
fxgit "$FXREAL" config user.name test
fxgit "$FXREAL" config user.email test@example.invalid
fxgit "$FXREAL" config commit.gpgsign false
STARTHEAD=$(fxgit "$FXREAL" rev-parse HEAD)

OUT=$(fxrelease "$FXREAL" --version 0.2.0-alpha --bump minor)
RC=$?

eq "a real cut succeeds" "0" "$RC"
eq "local main is unchanged -- the release commit lands on a new branch" \
	"$STARTHEAD" "$(fxgit "$FXREAL" rev-parse main)"
eq "the operator is left on the release branch" "release/v0.2.0-alpha" \
	"$(fxgit "$FXREAL" symbolic-ref --short HEAD)"
on_remote_branch() { fxgit "$FXREAL" ls-remote --exit-code --heads dev release/v0.2.0-alpha >/dev/null; }
true_ "the release branch was pushed to the remote" on_remote_branch
eq "remote main is unchanged -- nothing was published to it" "$STARTHEAD" \
	"$(GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git -C "$BARE" rev-parse refs/heads/main)"
# v0.1.0-alpha is mkfixture's baseline tag; v0.2.0-alpha and its lockstep
# namespaces are the ones a real cut must NOT create -- that is
# release-tag.sh's job, run only after this branch's pull request merges.
eq "no new tag was created -- that is release-tag.sh's job" "v0.1.0-alpha" \
	"$(fxgit "$FXREAL" tag --list 'v*' | tr '\n' ' ' | sed 's/ $//')"
true_ "the changelog was assembled" grep -q '^## \[0.2.0-alpha\]' "$FXREAL/CHANGELOG.md"
eq "the entry files were consumed" "0" \
	"$(find "$FXREAL/.changelog/unreleased" -name '*.md' ! -name README.md | wc -l | tr -d ' ')"
true_ "the entries README survived" test -f "$FXREAL/.changelog/unreleased/README.md"
true_ "the pins moved" grep -q 'go-xkms/sdk/go v0.2.0-alpha' "$FXREAL/go.mod"
eq "the commit message is the release commit" "chore(release): v0.2.0-alpha" \
	"$(fxgit "$FXREAL" log -1 --format=%s)"
true_ "the run names the pull request URL or says it could not" \
	grep -qE 'open a pull request|could not determine the repository URL' <<<"$OUT"
true_ "the run names release-tag as the next step" \
	grep -q 'make release-tag VERSION=0.2.0-alpha' <<<"$OUT"

# Preparing the same version again is refused: the branch now exists both
# locally and on the remote.
OUT2=$(fxrelease "$FXREAL" --version 0.2.0-alpha --bump minor)
RC2=$?
eq "preparing an already-prepared version is refused" "1" "$RC2"
true_ "the refusal names the existing local branch" \
	grep -q "local branch 'release/v0.2.0-alpha' already exists" <<<"$OUT2"

rm -rf "$FXROOT"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
