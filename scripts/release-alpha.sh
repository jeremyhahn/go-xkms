#!/usr/bin/env bash
#
# release-alpha.sh — cut an -alpha release of go-xkms.
#
# Usage:
#	scripts/release-alpha.sh --version X.Y.Z-alpha [--bump LEVEL] [--dry-run]
#	                         [--remote NAME] [--branch NAME]
#
#	--version   REQUIRED. The exact version to publish, e.g. 0.9.2-alpha.
#	--bump      Optional. patch|minor|major. Declares what KIND of release
#	            this is; refused unless it agrees with --version.
#	--dry-run   Rehearse every check and the pin rewrite against a scratch
#	            copy, print the diff, change nothing.
#	--remote    Remote to publish to (default: dev).
#	--branch    Branch releases are cut from (default: main).
#
# The version is STATED, never derived. Deriving it asks an open question --
# what is the greatest version anywhere? -- whose answer depends on local tags,
# remote tags, reachability, malformed tags, three lockstep namespaces and
# partial publications, and which grows a new edge case every time one is
# found. Validating a stated version asks a closed one against a fixed
# checklist: well-formed, strictly greater than the current in every lockstep
# namespace, and not already taken in any of them.
#
# Scope note: this script deliberately does NOT defend the seams between its
# first read and its final push against a concurrent writer. It refuses to run
# on a dirty tree or a non-empty index instead, which removes that class rather
# than guarding it. Making the remaining races unreachable means cutting from
# an isolated checkout, which is go-xkms#211 and needs an owner ruling.
set -euo pipefail

REMOTE=${REMOTE:-dev}
RELEASE_BRANCH=${RELEASE_BRANCH:-main}
GIT=${GIT:-git}

# The lockstep tag namespaces. Every release publishes exactly one tag in each,
# all pointing at the same commit (release-versioning.md P2). web/desktop is a
# module but not a published one -- it carries no tag namespace because it
# replaces all three siblings with local paths and is never resolved by a
# consumer.
TAG_NAMESPACES=("" "sdk/go/" "xkey/")

# The DECLARED reciprocal pin edges: every "<file> requires <module> at the
# release version" relationship in the repository, as "<file>:<module>".
#
# Declared, not discovered. A count of pins found at the current version
# compares equal when an edge is stale (counted in neither total) or deleted
# (absent from both), so the release passes while shipping a module that no
# longer pins its sibling. Naming each edge turns a deletion into a failure and
# a legitimate dependency change into a one-line edit reviewed alongside it.
#
# Re-derive after any module change:
#	git ls-tree -r --name-only HEAD | grep 'go.mod$'
#	grep -n 'jeremyhahn/go-xkms' <each>
PIN_EDGES=(
	"go.mod:github.com/jeremyhahn/go-xkms/sdk/go"
	"go.mod:github.com/jeremyhahn/go-xkms/xkey"
	"sdk/go/go.mod:github.com/jeremyhahn/go-xkms"
	"sdk/go/go.mod:github.com/jeremyhahn/go-xkms/xkey"
	"xkey/go.mod:github.com/jeremyhahn/go-xkms"
	"xkey/go.mod:github.com/jeremyhahn/go-xkms/sdk/go"
	"web/desktop/go.mod:github.com/jeremyhahn/go-xkms"
	"web/desktop/go.mod:github.com/jeremyhahn/go-xkms/sdk/go"
	"web/desktop/go.mod:github.com/jeremyhahn/go-xkms/xkey"
)

# Files the release commit is allowed to contain, and nothing else. DERIVED
# from PIN_EDGES rather than listed beside it: a go.mod declared as carrying an
# edge but omitted here would be rewritten and validated, then left out of the
# release commit -- a release that passes every check and ships a stale pin.
RELEASE_FILES=(VERSION)
for _edge in "${PIN_EDGES[@]}"; do
	_file=${_edge%%:*}
	case " ${RELEASE_FILES[*]} " in *" $_file "*) continue ;; esac
	RELEASE_FILES+=("$_file")
done
unset _edge _file

die() {
	printf 'release-alpha: %s\n' "$1" >&2
	exit 1
}

# ---------------------------------------------------------------------------
# Pure functions. Everything below this block reads or writes the repository;
# everything in it is a function of its arguments alone and is unit tested in
# test/scripts/release-alpha.test.sh.
# ---------------------------------------------------------------------------

# is_alpha_semver accepts only the shape this script knows how to handle.
# A glob such as `--match 'v*'` is not a version check: vfoo, v1 and
# v2026-08-21 all satisfy it and would be coerced to plausible-looking
# nonsense by any arithmetic downstream.
is_alpha_semver() {
	[[ $1 =~ ^v[0-9]+\.[0-9]+\.[0-9]+-alpha$ ]]
}

# escape_dots makes a version or module path literal for a BRE, where an
# unescaped `.` matches any character and v0.8.0-alpha would also match
# v0X8Y0-alpha.
escape_dots() {
	printf '%s' "${1//./\\.}"
}

# next_version advances one field of vMAJOR.MINOR.PATCH-alpha, zeroing the
# fields below it. Pre-1.0, MINOR is where breakage lives
# (release-versioning.md §1); the old target hardcoded PATCH+1 and could not
# express a breaking release at all.
next_version() {
	local v=${1#v} major minor patch
	IFS='.' read -r major minor patch <<<"${v%-alpha}"
	case $2 in
	major) major=$((10#$major + 1)); minor=0; patch=0 ;;
	minor) minor=$((10#$minor + 1)); patch=0 ;;
	patch) patch=$((10#$patch + 1)) ;;
	*) return 1 ;;
	esac
	printf 'v%d.%d.%d-alpha' "$major" "$minor" "$patch"
}

# version_gt is true when $1 sorts strictly after $2. Compared field by field
# rather than through `sort -V`, whose ordering rules are a property of the
# host's coreutils and not of semver.
version_gt() {
	local a=${1#v} b=${2#v} a1 a2 a3 b1 b2 b3
	IFS='.' read -r a1 a2 a3 <<<"${a%-alpha}"
	IFS='.' read -r b1 b2 b3 <<<"${b%-alpha}"
	if ((10#$a1 != 10#$b1)); then return $((10#$a1 > 10#$b1 ? 0 : 1)); fi
	if ((10#$a2 != 10#$b2)); then return $((10#$a2 > 10#$b2 ? 0 : 1)); fi
	if ((10#$a3 != 10#$b3)); then return $((10#$a3 > 10#$b3 ? 0 : 1)); fi
	return 1
}

# max_version prints the greatest well-formed -alpha version on stdin, or
# nothing when none is well-formed. Malformed input is discarded rather than
# coerced.
max_version() {
	local line best=""
	while read -r line; do
		[ -n "$line" ] || continue
		is_alpha_semver "$line" || continue
		if [ -z "$best" ] || version_gt "$line" "$best"; then
			best=$line
		fi
	done
	printf '%s' "$best"
}

# pin_version prints the version a go.mod requires a module at, or nothing.
#
# A go.mod carries our module paths in two shapes and only one is a pin:
#
#	require ( github.com/jeremyhahn/go-xkms v0.9.1-alpha )   <- a pin
#	replace ( github.com/jeremyhahn/go-xkms => ../ )         <- NOT a pin
#
# Inside a replace BLOCK the entry is indented and begins with the module path
# exactly like a require entry, and xkey/go.mod has its replace block FIRST --
# so anchoring on the path alone reads "=>" as the version. The version token
# is part of the pattern, not something read off afterwards. Demanding
# whitespace immediately after the path is what stops the bare go-xkms pattern
# from swallowing the /sdk/go and /xkey lines.
pin_version() {
	local file=$1 module=$2 line="" rest=""
	# `|| line=""` because grep exits 1 on no match, which would otherwise abort
	# the caller's assignment. `-m1` rather than `| head -1`: under pipefail,
	# head exiting first can SIGPIPE grep, and the `|| line=""` would then
	# discard a pin that WAS found and report the edge as missing.
	line=$(grep -m1 -E "^[[:space:]]*$(escape_dots "$module")[[:space:]]+v[0-9]" "$file" 2>/dev/null) || line=""
	read -r _ rest <<<"$line" || true
	printf '%s' "${rest%% *}"
}

# rewrite_pin moves one declared edge from $3 to $4, in place, in $1/$2.
#
# The pattern keeps a trailing `// indirect` rather than truncating it, and
# leaves a versionless `replace ... => ../..` line alone. The version cannot be
# followed by an optional group ending in `$`: in a BRE, `$` inside a group is
# a literal dollar sign and not an anchor, so `\([[:space:]]\|$\)` silently
# matches nothing at end of line.
rewrite_pin() {
	local root=$1 file=$2 module=$3 from=$4 to=$5
	local m; m=$(escape_dots "$module")
	local f; f=$(escape_dots "$from")
	sed -i "s|^\([[:space:]]*${m}[[:space:]]\{1,\}\)${f}\([[:space:]].*\)\{0,1\}$|\1${to}\2|" \
		"$root/$file"
}

# require_pins_at asserts every DECLARED edge exists under $1 and sits at $2.
# Returns 1 and reports every offending edge; a missing edge is reported as
# missing rather than silently skipped.
require_pins_at() {
	local root=$1 want=$2 phase=$3 edge file module got bad=""
	[ ${#PIN_EDGES[@]} -gt 0 ] ||
		die "PIN_EDGES is empty -- refusing to release without knowing which pins must move"
	for edge in "${PIN_EDGES[@]}"; do
		file=${edge%%:*}
		module=${edge#*:}
		if [ ! -f "$root/$file" ]; then
			bad+=$'\n'"  $file: missing file (expected to pin $module)"
			continue
		fi
		got=$(pin_version "$root/$file" "$module")
		if [ -z "$got" ]; then
			bad+=$'\n'"  $file: $module has no require pin -- the reciprocal edge was removed"
		elif [ "$got" != "$want" ]; then
			bad+=$'\n'"  $file: $module is at $got, want $want"
		fi
	done
	if [ -n "$bad" ]; then
		printf 'release-alpha: reciprocal pins are not all at %s (%s):%s\n' \
			"$want" "$phase" "$bad" >&2
		return 1
	fi
	return 0
}

# changelog_has_heading is true when $1 contains `## [$2]` at the START of a
# line, which is what .github/workflows/release.yml requires
# (`grep -qE "^## \[$VERSION\]"`). An unanchored substring search accepts text
# the workflow rejects -- a line reading `see ## [0.9.2-alpha] below` passes it
# -- and that is the one direction that costs a permanently published tag.
# Matched as an anchored FIXED string rather than by reusing the workflow's
# regex, whose unescaped dots make it looser than it reads: stricter here is
# safe, since a preflight failure publishes nothing.
changelog_has_heading() {
	[ -f "$1" ] || return 1
	awk -v h="## [$2]" 'index($0, h) == 1 { found = 1; exit } END { exit !found }' "$1"
}

# Sourced by the unit tests for the functions above; nothing below runs.
if [ "${RELEASE_ALPHA_LIB:-0}" = 1 ]; then
	return 0
fi

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

REQUESTED=""
BUMP=""
DRY_RUN=0

while [ $# -gt 0 ]; do
	case $1 in
	--version) [ $# -ge 2 ] || die "--version needs a value"; REQUESTED=$2; shift 2 ;;
	--version=*) REQUESTED=${1#--version=}; shift ;;
	--bump) [ $# -ge 2 ] || die "--bump needs a value"; BUMP=$2; shift 2 ;;
	--bump=*) BUMP=${1#--bump=}; shift ;;
	--remote) [ $# -ge 2 ] || die "--remote needs a value"; REMOTE=$2; shift 2 ;;
	--remote=*) REMOTE=${1#--remote=}; shift ;;
	--branch) [ $# -ge 2 ] || die "--branch needs a value"; RELEASE_BRANCH=$2; shift 2 ;;
	--branch=*) RELEASE_BRANCH=${1#--branch=}; shift ;;
	--dry-run) DRY_RUN=1; shift ;;
	-h | --help) sed -n '3,16p' "$0"; exit 0 ;;
	*) die "unknown argument '$1'" ;;
	esac
done

[ -n "$REQUESTED" ] || die "--version is required, e.g. 'make release-alpha VERSION=0.9.2-alpha'. The version is stated, not guessed"

NEXT=v${REQUESTED#v}
is_alpha_semver "$NEXT" ||
	die "--version '$REQUESTED' is not a X.Y.Z-alpha version"

case $BUMP in
"" | patch | minor | major) ;;
*) die "--bump must be patch, minor or major (got '$BUMP')" ;;
esac

# ---------------------------------------------------------------------------
# Preconditions. Nothing is written until all of them pass.
# ---------------------------------------------------------------------------

$GIT rev-parse --git-dir >/dev/null 2>&1 || die "not a git repository"
cd "$($GIT rev-parse --show-toplevel)" || die "could not reach the repository root"

# PROVENANCE, before content. Module tags cannot be withdrawn once a consumer
# has fetched them, so tagging from a feature branch or a detached HEAD is not
# recoverable by reverting -- only by burning a version.
BRANCH=$($GIT symbolic-ref -q --short HEAD 2>/dev/null) || BRANCH=""
[ -n "$BRANCH" ] || die "HEAD is detached -- check out $RELEASE_BRANCH first"
[ "$BRANCH" = "$RELEASE_BRANCH" ] ||
	die "on branch '$BRANCH' -- releases are cut from '$RELEASE_BRANCH' only. Pass --branch to override deliberately"

# A clean tree and an empty index are a PRECONDITION, not a race guard. The
# release commit takes whatever is staged, so refusing to start on a dirty tree
# deletes the "someone's unrelated edits were swept into the release" class
# outright, and makes the later `git add` of RELEASE_FILES exact by
# construction.
[ -z "$($GIT status --porcelain)" ] ||
	die "the working tree is not clean. A release commit must contain this release and nothing else; commit or stash your changes first"

# ---------------------------------------------------------------------------
# Version validation: a closed checklist over a stated version.
# ---------------------------------------------------------------------------

[ -f VERSION ] || die "VERSION not found at the repository root"
CURRENT=v$(tr -d ' \t\n' <VERSION)
is_alpha_semver "$CURRENT" ||
	die "the VERSION file holds '${CURRENT#v}', which is not a X.Y.Z-alpha version"

version_gt "$NEXT" "$CURRENT" ||
	die "$NEXT is not greater than the current version $CURRENT. Pass the version to publish: make release-alpha VERSION=<X.Y.Z-alpha>"

# --bump is a stated intent checked against the stated version, never a
# derivation. It is what makes a breaking release expressible: the old target
# hardcoded PATCH+1, so `VERSION=0.10.0-alpha BUMP=minor` was impossible to ask
# for and `VERSION=0.9.2-alpha BUMP=minor` is now refused as a mismatch.
if [ -n "$BUMP" ]; then
	EXPECTED=$(next_version "$CURRENT" "$BUMP")
	[ "$EXPECTED" = "$NEXT" ] ||
		die "--bump $BUMP on $CURRENT is $EXPECTED, but --version says $NEXT. Fix whichever one is wrong"
fi

# Strictly greater than the current tag in EVERY lockstep namespace, and taken
# in none of them. Asked of the local tag store; the atomic push below is what
# actually enforces it against the remote, since git refuses to move an
# existing remote tag without --force and an atomic push publishes nothing when
# any one ref is rejected.
for ns in "${TAG_NAMESPACES[@]}"; do
	label=${ns:-<root>}
	if $GIT rev-parse -q --verify "refs/tags/${ns}${NEXT}" >/dev/null; then
		die "tag ${ns}${NEXT} already exists -- $NEXT is taken in the $label namespace"
	fi
	ns_current=$($GIT tag --list "${ns}v*" | sed "s|^${ns}||" | max_version)
	[ -n "$ns_current" ] || continue
	version_gt "$NEXT" "$ns_current" ||
		die "$NEXT is not greater than $ns_current, the current tag in the $label namespace"
done

changelog_has_heading CHANGELOG.md "${NEXT#v}" ||
	die "CHANGELOG.md has no '## [${NEXT#v}]' section beginning a line. Add it and commit it first -- the release workflow fails the tag without it, AFTER the module tags have been pushed and become permanent"

require_pins_at . "$CURRENT" "before the rewrite" ||
	die "refusing to start a release from an inconsistent pin set"

printf 'release-alpha: %s -> %s (%d reciprocal pins, %d tags)\n' \
	"$CURRENT" "$NEXT" "${#PIN_EDGES[@]}" "${#TAG_NAMESPACES[@]}"

# ---------------------------------------------------------------------------
# Rehearsal. The rewrite runs against a scratch copy, so a dry run cannot
# leave a partially rewritten pin set behind however it exits -- which is why
# there is no restore trap here to get wrong.
# ---------------------------------------------------------------------------

if [ "$DRY_RUN" = 1 ]; then
	SCRATCH=$(mktemp -d) || die "could not create a scratch directory"
	trap 'rm -rf "$SCRATCH"' EXIT
	for f in "${RELEASE_FILES[@]}"; do
		mkdir -p "$SCRATCH/$(dirname "$f")"
		cp "$f" "$SCRATCH/$f"
	done
	printf '%s\n' "${NEXT#v}" >"$SCRATCH/VERSION"
	for edge in "${PIN_EDGES[@]}"; do
		rewrite_pin "$SCRATCH" "${edge%%:*}" "${edge#*:}" "$CURRENT" "$NEXT"
	done
	require_pins_at "$SCRATCH" "$NEXT" "after the rehearsed rewrite" ||
		die "the rehearsed rewrite did not move every pin -- a real release would have refused here too"
	for f in "${RELEASE_FILES[@]}"; do
		diff -u --label "a/$f" --label "b/$f" "$f" "$SCRATCH/$f" || true
	done
	printf 'release-alpha: DRY RUN -- would commit the diff above, then tag and atomically push:\n'
	for ns in "${TAG_NAMESPACES[@]}"; do printf '  %s%s\n' "$ns" "$NEXT"; done
	printf 'release-alpha: nothing was changed\n'
	exit 0
fi

# ---------------------------------------------------------------------------
# The release
# ---------------------------------------------------------------------------

printf '%s\n' "${NEXT#v}" >VERSION
for edge in "${PIN_EDGES[@]}"; do
	rewrite_pin . "${edge%%:*}" "${edge#*:}" "$CURRENT" "$NEXT"
done

require_pins_at . "$NEXT" "after the rewrite" ||
	die "the rewrite did not move every pin. Nothing has been committed, tagged or pushed; 'git checkout --' the files above to undo it"

$GIT add -- "${RELEASE_FILES[@]}" || die "could not stage the release files"
$GIT commit -q -m "chore(release): $NEXT" || die "the release commit failed"
RELEASE_COMMIT=$($GIT rev-parse HEAD) || die "could not resolve the release commit"

# Annotated AND signed, both required. Every existing tag in this repo is an
# annotated object, and agent-git.sh sets tag.gpgsign=true, under which a bare
# `git tag <name>` with no -m aborts with "fatal: no tag message?" -- so the old
# target was unusable by any project agent, which is the only thing that
# releases these repos. `-s` rather than `-a` because `-a` signs only when
# tag.gpgSign happens to be set, which silently gave agents signed tags and
# humans unsigned ones.
TAGS=()
for ns in "${TAG_NAMESPACES[@]}"; do
	t="${ns}${NEXT}"
	$GIT tag -s -m "$t" "$t" "$RELEASE_COMMIT" ||
		die "failed to create the signed tag $t. Configure a signing key (user.signingkey + gpg.format) or release through software/scripts/agent-git.sh. Tags created so far: ${TAGS[*]:-none}; nothing was pushed"
	TAGS+=("$t")
done

# The signature is confirmed to be ON the object before anything is published.
# `git tag -v` cannot answer this: SSH-signed tags need an allowedSignersFile
# to verify, which is not configured here, so a correctly signed tag reports as
# unverifiable. Reading the object answers the question this script owns --
# did signing happen -- without needing a trust store.
for t in "${TAGS[@]}"; do
	# Captured, not piped into `grep -q`: grep exits on the first match, and
	# under pipefail the resulting SIGPIPE on cat-file would read as a failed
	# check on a tag that is correctly signed.
	tag_object=$($GIT cat-file tag "$t") ||
		die "created tag $t but could not read it back. Nothing was pushed; remove the local tags with: git tag -d ${TAGS[*]}"
	grep -qE '^-----BEGIN (SSH|PGP) SIGNATURE-----' <<<"$tag_object" ||
		die "tag $t carries no signature. Nothing was pushed; remove the local tags with: git tag -d ${TAGS[*]}"
done

# Exactly the refs this run created, ALL OR NOTHING.
#
# `--tags` publishes every local tag, including leftovers from an abandoned
# attempt. And without `--atomic` a push of four refs is not a transaction: one
# rejected ref leaves the others published, which for a lockstep release is the
# worst outcome available, since module tags are immutable once a consumer has
# fetched them and a half-published release can only be followed by another
# version.
REFSPECS=("$RELEASE_COMMIT:refs/heads/$RELEASE_BRANCH")
for t in "${TAGS[@]}"; do REFSPECS+=("refs/tags/$t:refs/tags/$t"); done

$GIT push --atomic "$REMOTE" "${REFSPECS[@]}" ||
	die "the atomic push was refused, so NOTHING was published. The release commit and tags are still local: 'git tag -d ${TAGS[*]}' and 'git reset --hard HEAD~1' to discard them"

printf 'release-alpha: published %s to %s (%s)\n' "$NEXT" "$REMOTE" "${TAGS[*]}"
