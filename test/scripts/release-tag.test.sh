#!/usr/bin/env bash
#
# End-to-end tests for scripts/release-tag.sh -- step two of the two-step
# release flow (go-xkms#419, go-xkms#211). Every fixture is a throwaway git
# repository under mktemp -d with its own bare "dev" remote: release-tag.sh's
# whole job is fetching that remote and refusing unless what it finds there
# is exactly right, so a fixture with no remote could not exercise it at all.
#
# The pure functions release-tag.sh reuses (is_alpha_semver, escape_dots,
# require_pins_at, changelog_has_heading, TAG_NAMESPACES, ...) are already
# covered by test/scripts/release-alpha.test.sh, which sources
# scripts/release-alpha.sh the same way release-tag.sh does. This file only
# covers what release-tag.sh adds: the fetch, the HEAD/VERSION/reachability
# assertions, and the tag creation, signing and atomic push.
#
# Tags are real annotated, SSH-signed objects here -- signed with this
# repository's own agent key
# (~/.agent-identity/keys/agent-go-xkms.key), never the
# owner's hardware key, and only ever inside a throwaway fixture removed at
# the end of the run.
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
AGENT_KEY="${RELEASE_TAG_TEST_SIGNING_KEY:-$HOME/.agent-identity/keys/agent-go-xkms.key}"

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

section() { printf '\n%s\n' "$1"; }

if [ ! -f "$AGENT_KEY" ]; then
	printf 'release-tag.test: no signing key at %s -- skipping (set RELEASE_TAG_TEST_SIGNING_KEY)\n' "$AGENT_KEY" >&2
	printf '\n0 passed, 0 failed\n'
	exit 0
fi

# ---------------------------------------------------------------------------
# Fixture plumbing, shared by every scenario below.
# ---------------------------------------------------------------------------

FXROOT=$(mktemp -d)
trap 'rm -rf "$FXROOT"' EXIT

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

mkbare() {
	local b
	b=$(mktemp -d -p "$FXROOT")/bare.git
	GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git init -q --bare -b main "$b" >/dev/null
	printf '%s' "$b"
}

# mkfixture builds a throwaway repository at v0.1.0-alpha, every declared pin
# edge consistent, signing configured with THIS repository's agent key
# (never the owner's), a bare "dev" remote added and main pushed to it.
# Prints the bare remote's path.
mkfixture() {
	local r=$1 x=github.com/jeremyhahn/go-xkms bare
	mkdir -p "$r/scripts" "$r/.changelog/unreleased"
	printf '0.1.0-alpha\n' >"$r/VERSION"
	fxmod "$r" go.mod "$x" "$x/sdk/go" "$x/xkey"
	fxmod "$r" sdk/go/go.mod "$x/sdk/go" "$x" "$x/xkey"
	fxmod "$r" xkey/go.mod "$x/xkey" "$x" "$x/sdk/go"
	fxmod "$r" web/desktop/go.mod "$x/web/desktop" "$x" "$x/sdk/go" "$x/xkey"
	printf '# Changelog\n\n## [Unreleased]\n\n## [0.1.0-alpha] - 2026-01-01\n\n### Fixed\n\n- old entry\n' \
		>"$r/CHANGELOG.md"
	printf 'contributor notes\n' >"$r/.changelog/unreleased/README.md"
	cp "$ROOT/scripts/release-alpha.sh" "$ROOT/scripts/release-tag.sh" "$r/scripts/"
	fxgit "$r" init -q -b main
	fxgit "$r" config user.name test
	fxgit "$r" config user.email test@example.invalid
	fxgit "$r" config user.signingkey "$AGENT_KEY"
	fxgit "$r" config gpg.format ssh
	fxgit "$r" add -A
	fxgit "$r" -c commit.gpgsign=false commit -q -m "fixture"
	fxgit "$r" tag v0.1.0-alpha
	bare=$(mkbare)
	fxgit "$r" remote add dev "$bare"
	fxgit "$r" push -q dev main
	printf '%s' "$bare"
}

# mkrelease_commit reproduces exactly what release-alpha.sh's real cut leaves
# on the release branch: VERSION bumped, every pin moved, a CHANGELOG heading
# added, one commit titled "chore(release): <version><suffix>" -- the suffix
# is how a squash merge's " (#<pr>)" is exercised.
mkrelease_commit() { # mkrelease_commit <repo> <version-with-v> [<subject-suffix>]
	local r=$1 v=$2 suffix=${3:-}
	printf '%s\n' "${v#v}" >"$r/VERSION"
	sed -i "s/v0\.1\.0-alpha/$v/" "$r/go.mod" "$r/sdk/go/go.mod" "$r/xkey/go.mod" "$r/web/desktop/go.mod"
	sed -i "s/## \[Unreleased\]/## [Unreleased]\n\n## [${v#v}] - 2026-02-02/" "$r/CHANGELOG.md"
	fxgit "$r" add -A
	fxgit "$r" -c commit.gpgsign=false commit -q -m "chore(release): ${v}${suffix}"
}

fxtag() { # fxtag <repo> <args...>
	local r=$1
	shift
	(cd "$r" && GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
		bash scripts/release-tag.sh "$@" 2>&1)
}

# ---------------------------------------------------------------------------

section "HEAD must equal the fetched remote tip"

FXSTALE="$FXROOT/stale-head"
BARE=$(mkfixture "$FXSTALE")
mkrelease_commit "$FXSTALE" v0.2.0-alpha
fxgit "$FXSTALE" push -q dev main
# Drop the release commit LOCALLY without telling the remote: HEAD no longer
# equals what dev/main was just fetched to.
fxgit "$FXSTALE" reset -q --hard HEAD~1

OUT=$(fxtag "$FXSTALE" --version 0.2.0-alpha)
RC=$?
eq "a local HEAD behind the fetched remote tip is refused" "1" "$RC"
true_ "the refusal names the fetched tip" grep -q 'fetched tip' <<<"$OUT"

section "on the wrong branch is refused"

FXBRANCH="$FXROOT/wrong-branch"
BARE=$(mkfixture "$FXBRANCH")
mkrelease_commit "$FXBRANCH" v0.2.0-alpha
fxgit "$FXBRANCH" push -q dev main
fxgit "$FXBRANCH" checkout -q -b not-main

OUT=$(fxtag "$FXBRANCH" --version 0.2.0-alpha)
RC=$?
eq "a checkout on a non-release branch is refused" "1" "$RC"
true_ "the refusal names the branch it is on" grep -q "on branch 'not-main'" <<<"$OUT"

section "VERSION at the fetched tip must equal --version"

FXVER="$FXROOT/version-mismatch"
BARE=$(mkfixture "$FXVER")
mkrelease_commit "$FXVER" v0.2.0-alpha
fxgit "$FXVER" push -q dev main

OUT=$(fxtag "$FXVER" --version 0.3.0-alpha)
RC=$?
eq "a --version not matching VERSION at the tip is refused" "1" "$RC"
true_ "the refusal quotes both versions" \
	grep -q "VERSION at dev/main is '0.2.0-alpha', not '0.3.0-alpha'" <<<"$OUT"

section "the release commit must be reachable"

FXNOCOMMIT="$FXROOT/no-release-commit"
BARE=$(mkfixture "$FXNOCOMMIT")
# VERSION reads 0.2.0-alpha, but no commit carrying the documented
# "chore(release): v0.2.0-alpha" message produced it -- release-alpha.sh was
# bypassed.
printf '0.2.0-alpha\n' >"$FXNOCOMMIT/VERSION"
sed -i "s/v0\.1\.0-alpha/v0.2.0-alpha/" \
	"$FXNOCOMMIT/go.mod" "$FXNOCOMMIT/sdk/go/go.mod" "$FXNOCOMMIT/xkey/go.mod" "$FXNOCOMMIT/web/desktop/go.mod"
sed -i "s/## \[Unreleased\]/## [Unreleased]\n\n## [0.2.0-alpha] - 2026-02-02/" "$FXNOCOMMIT/CHANGELOG.md"
fxgit "$FXNOCOMMIT" add -A
fxgit "$FXNOCOMMIT" -c commit.gpgsign=false commit -q -m "manually bump the version, bypassing release-alpha.sh"
fxgit "$FXNOCOMMIT" push -q dev main

OUT=$(fxtag "$FXNOCOMMIT" --version 0.2.0-alpha)
RC=$?
eq "a VERSION bump with no matching release commit is refused" "1" "$RC"
true_ "the refusal names the missing commit message" \
	grep -q "no 'chore(release): v0.2.0-alpha' commit is reachable" <<<"$OUT"

section "the pins at the release commit are re-checked, not trusted"

FXBADPINS="$FXROOT/bad-pins"
BARE=$(mkfixture "$FXBADPINS")
printf '0.2.0-alpha\n' >"$FXBADPINS/VERSION"
# Every pin except sdk/go's own move -- a genuinely inconsistent release
# commit, the kind review is supposed to catch before it merges.
sed -i "s/v0\.1\.0-alpha/v0.2.0-alpha/" \
	"$FXBADPINS/go.mod" "$FXBADPINS/xkey/go.mod" "$FXBADPINS/web/desktop/go.mod"
sed -i "s/## \[Unreleased\]/## [Unreleased]\n\n## [0.2.0-alpha] - 2026-02-02/" "$FXBADPINS/CHANGELOG.md"
fxgit "$FXBADPINS" add -A
fxgit "$FXBADPINS" -c commit.gpgsign=false commit -q -m "chore(release): v0.2.0-alpha"
fxgit "$FXBADPINS" push -q dev main

OUT=$(fxtag "$FXBADPINS" --version 0.2.0-alpha)
RC=$?
eq "an inconsistent pin set at the release commit is refused" "1" "$RC"
true_ "the refusal names the pin check" grep -q 'reciprocal pins' <<<"$OUT"

section "the CHANGELOG heading at the release commit is re-checked"

FXNOHEADING="$FXROOT/no-heading"
BARE=$(mkfixture "$FXNOHEADING")
printf '0.2.0-alpha\n' >"$FXNOHEADING/VERSION"
sed -i "s/v0\.1\.0-alpha/v0.2.0-alpha/" \
	"$FXNOHEADING/go.mod" "$FXNOHEADING/sdk/go/go.mod" "$FXNOHEADING/xkey/go.mod" "$FXNOHEADING/web/desktop/go.mod"
# CHANGELOG.md is deliberately left without a "## [0.2.0-alpha]" heading.
fxgit "$FXNOHEADING" add -A
fxgit "$FXNOHEADING" -c commit.gpgsign=false commit -q -m "chore(release): v0.2.0-alpha"
fxgit "$FXNOHEADING" push -q dev main

OUT=$(fxtag "$FXNOHEADING" --version 0.2.0-alpha)
RC=$?
eq "a missing CHANGELOG heading at the release commit is refused" "1" "$RC"
true_ "the refusal names the heading check" grep -q 'CHANGELOG.md at' <<<"$OUT"

section "success: three signed tags, created and pushed atomically"

FXOK="$FXROOT/ok"
BARE=$(mkfixture "$FXOK")
mkrelease_commit "$FXOK" v0.2.0-alpha " (#42)" # squash-merge shape
fxgit "$FXOK" push -q dev main
RELEASE_COMMIT=$(fxgit "$FXOK" rev-parse HEAD)

OUT=$(fxtag "$FXOK" --version 0.2.0-alpha)
RC=$?
eq "a clean, matching, reachable release commit succeeds" "0" "$RC"
eq "the three lockstep tags exist locally" "sdk/go/v0.2.0-alpha v0.2.0-alpha xkey/v0.2.0-alpha" \
	"$(fxgit "$FXOK" tag --list 'v0.2.0-alpha' 'sdk/go/v0.2.0-alpha' 'xkey/v0.2.0-alpha' | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
for t in v0.2.0-alpha sdk/go/v0.2.0-alpha xkey/v0.2.0-alpha; do
	eq "$t points at the release commit" "$RELEASE_COMMIT" \
		"$(fxgit "$FXOK" rev-list -n1 "$t")"
	true_ "$t is signed" \
		bash -c "GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git -C '$FXOK' cat-file tag '$t' | grep -qE '^-----BEGIN (SSH|PGP) SIGNATURE-----'"
	on_bare() { GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git -C "$BARE" rev-parse -q --verify "refs/tags/$1" >/dev/null; }
	true_ "$t was pushed to the remote" on_bare "$t"
done
true_ "the run reports what it published" grep -q 'published v0.2.0-alpha to dev' <<<"$OUT"

# Re-running for the same version is refused: the namespace is already taken,
# locally and on the remote alike.
OUT2=$(fxtag "$FXOK" --version 0.2.0-alpha)
RC2=$?
eq "tagging an already-tagged version again is refused" "1" "$RC2"
true_ "the refusal names the taken namespace" grep -q 'already exists' <<<"$OUT2"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
