#!/usr/bin/env bash
#
# release-tag.sh — TAG a go-xkms release already merged to main. This is step
# two of the two-step release flow (go-xkms#419, go-xkms#211 "option B"):
# step one is `scripts/release-alpha.sh` / `make release-alpha`, which
# prepares a pull request and stops. Run this only after that pull request
# has been reviewed and merged.
#
# Usage:
#	scripts/release-tag.sh --version X.Y.Z-alpha [--remote NAME] [--branch NAME]
#
#	--version   REQUIRED. The exact version to tag, e.g. 0.9.2-alpha. Must
#	            match what the merged release commit set VERSION to.
#	--remote    Remote to fetch from and push the tags to (default: dev).
#	--branch    The branch a release is tagged off (default: main).
#
# What this script asserts, fetched fresh every time, before it creates
# anything (go-xkms#211's "fetch-and-assert" option — a disposable checkout
# was considered and declined; this still runs in the operator's own
# checkout, but trusts nothing it did not just fetch):
#
#	1. HEAD is --branch, checked out locally, and is BYTE-IDENTICAL to the
#	   just-fetched --remote/--branch. Not merely a descendant or ancestor —
#	   equal. Tags are created from that one commit and no other.
#	2. VERSION at that commit, read from the git object rather than the
#	   working tree, is exactly --version.
#	3. A commit reachable from that tip has the exact release-commit message
#	   scripts/release-alpha.sh produces for --version -- so a VERSION file
#	   that merely happens to already read the right value (say, because
#	   nothing has bumped it since a previous release) cannot pass this
#	   script off as a reviewed release. It came from the documented
#	   issue -> branch -> PR -> review -> merge flow, or this refuses.
#	4. The reciprocal pins and the CHANGELOG heading are still exactly what
#	   release-alpha.sh left them as -- re-checked here, not merely trusted,
#	   because a tag is immutable and this is the last chance to refuse
#	   before one exists.
#
# Only then does it create the three lockstep tags -- annotated, signed, and
# confirmed signed on the object before anything is pushed -- and push them
# atomically. See docs/release-engineering/.
set -euo pipefail

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Reused, not redeclared: TAG_NAMESPACES, PIN_EDGES, is_alpha_semver,
# escape_dots, require_pins_at, changelog_has_heading and the rest of
# release-alpha.sh's pure functions are exactly as true here as they are
# there, and a second copy is a copy that drifts. RELEASE_ALPHA_LIB=1 sources
# only the declarations and returns before release-alpha.sh reads a single
# argument or touches the repository.
RELEASE_ALPHA_LIB=1 . "$SELF_DIR/release-alpha.sh"

die() {
	printf 'release-tag: %s\n' "$1" >&2
	exit 1
}

REMOTE=${REMOTE:-dev}
RELEASE_BRANCH=${RELEASE_BRANCH:-main}
GIT=${GIT:-git}

REQUESTED=""
while [ $# -gt 0 ]; do
	case $1 in
	--version) [ $# -ge 2 ] || die "--version needs a value"; REQUESTED=$2; shift 2 ;;
	--version=*) REQUESTED=${1#--version=}; shift ;;
	--remote) [ $# -ge 2 ] || die "--remote needs a value"; REMOTE=$2; shift 2 ;;
	--remote=*) REMOTE=${1#--remote=}; shift ;;
	--branch) [ $# -ge 2 ] || die "--branch needs a value"; RELEASE_BRANCH=$2; shift 2 ;;
	--branch=*) RELEASE_BRANCH=${1#--branch=}; shift ;;
	-h | --help) sed -n '3,14p' "$0"; exit 0 ;;
	*) die "unknown argument '$1'" ;;
	esac
done

[ -n "$REQUESTED" ] || die "--version is required, e.g. 'make release-tag VERSION=0.9.2-alpha'"
NEXT=v${REQUESTED#v}
is_alpha_semver "$NEXT" || die "--version '$REQUESTED' is not a X.Y.Z-alpha version"

$GIT rev-parse --git-dir >/dev/null 2>&1 || die "not a git repository"
cd "$($GIT rev-parse --show-toplevel)" || die "could not reach the repository root"

# ---------------------------------------------------------------------------
# 1. HEAD is --branch, and is byte-identical to the just-fetched remote tip.
# ---------------------------------------------------------------------------

printf 'release-tag: fetching %s/%s...\n' "$REMOTE" "$RELEASE_BRANCH"
$GIT fetch --quiet "$REMOTE" "$RELEASE_BRANCH" || die "could not fetch $RELEASE_BRANCH from $REMOTE"
REMOTE_TIP=$($GIT rev-parse FETCH_HEAD) || die "could not resolve the fetched tip of $REMOTE/$RELEASE_BRANCH"
$GIT fetch --quiet --tags "$REMOTE" || die "could not fetch tags from $REMOTE"

LOCAL_BRANCH=$($GIT symbolic-ref -q --short HEAD 2>/dev/null) || LOCAL_BRANCH=""
[ -n "$LOCAL_BRANCH" ] ||
	die "HEAD is detached -- check out $RELEASE_BRANCH, up to date with $REMOTE/$RELEASE_BRANCH, first"
[ "$LOCAL_BRANCH" = "$RELEASE_BRANCH" ] ||
	die "on branch '$LOCAL_BRANCH' -- releases are tagged from '$RELEASE_BRANCH' only. Pass --branch to override deliberately"

LOCAL_HEAD=$($GIT rev-parse HEAD) || die "could not resolve HEAD"
[ "$LOCAL_HEAD" = "$REMOTE_TIP" ] ||
	die "HEAD ($LOCAL_HEAD) is not $REMOTE/$RELEASE_BRANCH's fetched tip ($REMOTE_TIP) -- fast-forward first: git merge --ff-only $REMOTE/$RELEASE_BRANCH"

# ---------------------------------------------------------------------------
# 2. VERSION at that exact commit, read from the object, is --version.
# ---------------------------------------------------------------------------

FILE_VERSION=$($GIT show "$REMOTE_TIP:VERSION" 2>/dev/null | tr -d ' \t\n') ||
	die "could not read VERSION at $REMOTE_TIP"
[ "$FILE_VERSION" = "${NEXT#v}" ] ||
	die "VERSION at $REMOTE/$RELEASE_BRANCH is '$FILE_VERSION', not '${NEXT#v}' -- fetch and confirm the right release pull request merged before tagging"

# ---------------------------------------------------------------------------
# 3. The release commit release-alpha.sh produced for --version is reachable
# from this tip -- not merely "VERSION happens to already read right".
# GitHub/Gitea-style squash merges append " (#<pr>)" to the original subject,
# so both shapes are accepted; nothing else is.
# ---------------------------------------------------------------------------

NEXT_RE=$(escape_dots "$NEXT")
RELEASE_COMMIT=$($GIT log --format=%H -E \
	--grep="^chore\(release\): ${NEXT_RE}( \(#[0-9]+\))?\$" \
	"$REMOTE_TIP" -1) || RELEASE_COMMIT=""
[ -n "$RELEASE_COMMIT" ] ||
	die "no 'chore(release): $NEXT' commit is reachable from $REMOTE/$RELEASE_BRANCH -- merge the release pull request (scripts/release-alpha.sh) first"

# ---------------------------------------------------------------------------
# 4. The pins and the CHANGELOG heading, re-checked against the object rather
# than trusted from review -- the last refusal available before a tag, which
# cannot be withdrawn, exists.
# ---------------------------------------------------------------------------

TAGROOT=$(mktemp -d) || die "could not create a scratch directory for $RELEASE_COMMIT"
trap 'rm -rf "$TAGROOT"' EXIT
$GIT archive --format=tar "$RELEASE_COMMIT" | (cd "$TAGROOT" && tar -xf -) ||
	die "could not materialize $RELEASE_COMMIT"

require_pins_at "$TAGROOT" "$NEXT" "at the release commit" ||
	die "refusing to tag $NEXT -- the reciprocal pins at $RELEASE_COMMIT are not all at $NEXT"
changelog_has_heading "$TAGROOT/CHANGELOG.md" "${NEXT#v}" ||
	die "refusing to tag $NEXT -- CHANGELOG.md at $RELEASE_COMMIT has no '## [${NEXT#v}]' section beginning a line"

# Strictly greater than the current tag in EVERY lockstep namespace, and taken
# in none of them -- against the tags just fetched, which is this script's
# only read of them: release-alpha.sh's check of the same shape is a preflight
# convenience, not the enforcement point. This IS the enforcement point, ahead
# of the atomic push, which enforces it again against the remote by refusing a
# tag move outright.
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

printf 'release-tag: %s at %s (%d tags)\n' "$NEXT" "$RELEASE_COMMIT" "${#TAG_NAMESPACES[@]}"

# ---------------------------------------------------------------------------
# The tags.
# ---------------------------------------------------------------------------

TAGS=()

# cleanup_hint names everything this run created locally. Nothing has been
# published at any point it is reached -- the push below is the only
# publishing step, and it is all-or-nothing.
cleanup_hint() {
	[ ${#TAGS[@]} -eq 0 ] && { printf 'nothing was written; there is nothing to undo'; return; }
	printf 'Nothing was pushed; undo the local state with: git tag -d %s' "${TAGS[*]}"
}

# Annotated AND signed, both required. Every existing tag in this repo is an
# annotated object, and agent-git.sh sets tag.gpgsign=true, under which a bare
# `git tag <name>` with no -m aborts with "fatal: no tag message?" -- so a
# bare target would be unusable by any project agent, which is the only thing
# that releases these repos. `-s` rather than `-a` because `-a` signs only
# when tag.gpgSign happens to be set, which silently gives agents signed tags
# and humans unsigned ones.
for ns in "${TAG_NAMESPACES[@]}"; do
	t="${ns}${NEXT}"
	$GIT tag -s -m "$t" "$t" "$RELEASE_COMMIT" ||
		die "failed to create the signed tag $t. Configure a signing key (user.signingkey + gpg.format) or release through software/scripts/agent-git.sh. $(cleanup_hint)"
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
		die "created tag $t but could not read it back. $(cleanup_hint)"
	grep -qE '^-----BEGIN (SSH|PGP) SIGNATURE-----' <<<"$tag_object" ||
		die "tag $t carries no signature. $(cleanup_hint)"
done

# Exactly the three refs this run created, ALL OR NOTHING.
#
# `--tags` publishes every local tag, including leftovers from an abandoned
# attempt. Without `--atomic` a push of three refs is not a transaction: one
# rejected ref leaves the others published, which for a lockstep release is
# the worst outcome available, since module tags are immutable once a
# consumer has fetched them.
REFSPECS=()
for t in "${TAGS[@]}"; do REFSPECS+=("refs/tags/$t:refs/tags/$t"); done

$GIT push --atomic "$REMOTE" "${REFSPECS[@]}" ||
	die "the atomic push was refused, so NOTHING was published. The tags are still local. $(cleanup_hint)"

printf 'release-tag: published %s to %s (%s)\n' "$NEXT" "$REMOTE" "${TAGS[*]}"
