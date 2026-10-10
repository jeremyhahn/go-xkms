#!/usr/bin/env bash
#
# release-alpha.sh — PREPARE an -alpha release of go-xkms. It stops at a pull
# request; it never publishes.
#
# Usage:
#	scripts/release-alpha.sh --version X.Y.Z-alpha [--bump LEVEL] [--dry-run]
#	                         [--remote NAME] [--branch NAME]
#
#	--version   REQUIRED. The exact version to publish, e.g. 0.9.2-alpha.
#	--bump      Optional. patch|minor|major. Declares what KIND of release
#	            this is; refused unless it agrees with --version. The
#	            exported-API growth gate below does not depend on this flag
#	            being given — see its comment.
#	--dry-run   Rehearse every check, the pin rewrite AND the changelog
#	            assembly against a scratch copy of the fetched remote tip;
#	            print the diff, change nothing, push nothing.
#	--remote    Remote to fetch from and push the release branch to
#	            (default: dev).
#	--branch    The branch releases are cut from (default: main). Overriding
#	            it is the only way to rehearse against a branch other than
#	            main.
#	FORGE_TOKEN Environment, REQUIRED. The project agent's forge API token,
#	            used to open the pull request.
#
# WHAT THIS SCRIPT DOES, and where the rest of the release happens
# (go-xkms#419, go-xkms#211 "option B"):
#
#	1. Fetches --branch from --remote and reads VERSION, the reciprocal
#	   pins and CHANGELOG.md from THAT fetched tip, never from whatever
#	   happens to be checked out locally — a stale local main cannot pass a
#	   check it never reads.
#	2. Validates the requested version, the pin set, the changelog heading,
#	   and refuses a release that grows the exported Go API under an
#	   effective PATCH bump.
#	3. On a real (non-dry-run) cut: checks out a new branch
#	   release/X.Y.Z-alpha from the fetched tip, assembles the changelog,
#	   moves the pins, bumps VERSION, commits, and pushes THE BRANCH ONLY.
#	   It then opens the pull request into --branch, titled exactly
#	   "chore(release): vX.Y.Z-alpha", on the forge --remote's own URL names
#	   (ssh, scp-like or http form), prints its URL and stops.
#
# It used to also create the three lockstep tags and push them, atomically,
# to main — with no pull request anywhere in that path (go-xkms#419: two
# releases raced for the same base because the tooling path had no review
# gate the documented issue → branch → PR → review → merge flow provides).
# That step is now `scripts/release-tag.sh` / `make release-tag`, run only
# after this script's pull request has been reviewed and merged. See
# docs/release-engineering/.
#
# The version is STATED, never derived. Deriving it asks an open question --
# what is the greatest version anywhere? -- whose answer depends on local tags,
# remote tags, reachability, malformed tags, three lockstep namespaces and
# partial publications, and which grows a new edge case every time one is
# found. Validating a stated version asks a closed one against a fixed
# checklist: well-formed, strictly greater than the current in every lockstep
# namespace, and not already taken in any of them.
#
# Scope note: fetching --branch and reading from that tip (rather than a fully
# isolated, disposable checkout) is go-xkms#211's "fetch-and-assert" option,
# not its "cut from a disposable checkout" option — the latter was considered
# and declined. This script still writes into the operator's own working
# tree/index for the real cut, and still refuses to run on a dirty tree or a
# non-empty index rather than defending every seam between its first read and
# its last push against a concurrent writer.
set -euo pipefail

REMOTE=${REMOTE:-dev}
RELEASE_BRANCH=${RELEASE_BRANCH:-main}
GIT=${GIT:-git}
GO=${GO:-go}
CURL=${CURL:-curl}

# The lockstep tag namespaces. Every release publishes exactly one tag in each,
# all pointing at the same commit (release-versioning.md P2). web/desktop is a
# module but not a published one -- it carries no tag namespace because it
# replaces all three siblings with local paths and is never resolved by a
# consumer. Tags themselves are no longer created here — scripts/release-tag.sh
# owns TAG_NAMESPACES too, kept in step with this list deliberately — but the
# namespaces are still the closed set this script checks the requested version
# against before it prepares anything.
TAG_NAMESPACES=("" "sdk/go/" "xkey/")

# The modules whose exported Go API the growth gate below compares. Same three
# as TAG_NAMESPACES, named without the trailing slash a directory path does not
# carry, and without web/desktop for the same reason it carries no tag
# namespace: nothing ever resolves it as a versioned dependency.
API_MODULES=("." "sdk/go" "xkey")

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

# bump_level derives patch|minor|major from two well-formed versions by
# comparing MAJOR and MINOR alone -- it never reads --bump. --bump is a
# DECLARED intent, cross-checked against --version earlier and only ever
# equal to what this function would derive when it is given at all (see the
# growth-gate comment below for why the derivation, not the flag, is what
# gates it). $1 must be strictly less than $2; callers only ever pass
# (CURRENT, NEXT) after version_gt has already confirmed that.
bump_level() {
	local cur=${1#v} nxt=${2#v} c1 c2 c3 n1 n2 n3
	IFS='.' read -r c1 c2 c3 <<<"${cur%-alpha}"
	IFS='.' read -r n1 n2 n3 <<<"${nxt%-alpha}"
	if ((10#$n1 != 10#$c1)); then
		printf 'major'
	elif ((10#$n2 != 10#$c2)); then
		printf 'minor'
	else
		printf 'patch'
	fi
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

# changelog_entries_pending is true when $1 holds at least one .changelog entry
# file (any *.md except README.md). Implemented WITHOUT a pipeline on purpose:
# `find ... | read -r _` under `set -o pipefail` fails as soon as there are
# TWO entries -- read exits after the first line, find takes SIGPIPE and exits
# 141, pipefail propagates it, and the assembler is skipped exactly when a
# release has the most to assemble (opencode finding on go-xkms#388).
# Command substitution has no writer to signal; `-print -quit` stops find at
# the first match so the answer is O(1) regardless of how many entries exist.
changelog_entries_pending() {
	[ -d "$1" ] || return 1
	[ -n "$(find "$1" -maxdepth 1 -name '*.md' ! -name 'README.md' -print -quit 2>/dev/null)" ]
}

# forge_repo_url prints the forge's web URL for a repository,
# "<scheme>://<host>[:<port>]/<owner>/<repo>" (no trailing .git), from the
# git remote URL it is pushed through. Both halves come from the one URL, so
# the pull request lands on the server the branch was pushed to:
#
#	ssh://[user@]host[:sshport]/owner/repo   -> http://host:3001/owner/repo
#	[user@]host:owner/repo                   -> http://host:3001/owner/repo
#	http[s]://[user[:pass]@]host[:port]/owner/repo -> as written, minus userinfo
#
# An SSH remote names the SSH port, not the web one, so it maps to
# GITEA_HTTP_PORT (default 3001), as scripts/gitea-host.sh does for origin.
# Prints nothing for a shape that names no forge (a local path, a file://
# URL, an empty string) or that has no owner/repo path.
forge_repo_url() {
	local url=$1 scheme=http hostport path
	case "$url" in
	ssh://*)
		hostport=${url#ssh://}
		path=${hostport#*/}
		hostport=${hostport%%/*}
		hostport="${hostport%%:*}:${GITEA_HTTP_PORT:-3001}"
		;;
	http://* | https://*)
		scheme=${url%%://*}
		hostport=${url#*://}
		path=${hostport#*/}
		hostport=${hostport%%/*}
		;;
	*://*) return 0 ;;
	*:*)
		# git reads a colon before any slash as scp-like syntax; a slash
		# first makes it a local path such as ./dir:name.
		hostport=${url%%:*}
		[[ $hostport != */* ]] || return 0
		path=${url#*:}
		hostport="${hostport}:${GITEA_HTTP_PORT:-3001}"
		;;
	*) return 0 ;;
	esac
	hostport=${hostport##*@}
	path=${path%/}
	path=${path%.git}
	[[ -n ${hostport%%:*} && $path == */* && $path != */*/* ]] || return 0
	printf '%s://%s/%s' "$scheme" "$hostport" "$path"
}

# json_string prints $1 as a JSON string literal, escaping the backslash and
# the double quote. That is complete for every value the pull request is
# built from: a validated version, fixed text, and branch names, in which
# git check-ref-format already forbids control characters.
json_string() {
	local s=${1//\\/\\\\}
	printf '"%s"' "${s//\"/\\\"}"
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
	-h | --help) sed -n '3,24p' "$0"; exit 0 ;;
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
# Preconditions that need neither the network nor the fetched tip.
# ---------------------------------------------------------------------------

$GIT rev-parse --git-dir >/dev/null 2>&1 || die "not a git repository"
cd "$($GIT rev-parse --show-toplevel)" || die "could not reach the repository root"

# A clean tree and an empty index are a PRECONDITION, not a race guard. The
# real cut below checks out a NEW branch from the fetched remote tip, which
# git refuses to do over uncommitted changes it would have to discard or
# carry; refusing here turns that into one plain message instead of a raw git
# error, and deletes the "someone's unrelated edits were swept into the
# release" class outright.
[ -z "$($GIT status --porcelain)" ] ||
	die "the working tree is not clean. A release commit must contain this release and nothing else; commit or stash your changes first"

BRANCH_NAME="release/$NEXT"
# The release commit's subject and the pull request's title, exactly:
# scripts/release-tag.sh looks for this commit on --branch before tagging.
RELEASE_TITLE="chore(release): $NEXT"

# Scratch directories this run creates, removed on every exit path. Declared
# before the first mktemp call, not after: a die() between here and the first
# `SCRATCH_DIRS+=(...)` still runs this trap, over an empty array, which is a
# no-op rather than a missing variable.
SCRATCH_DIRS=()
trap 'rm -rf "${SCRATCH_DIRS[@]}"' EXIT

# cleanup_hint names how to undo whatever this run left behind LOCALLY.
# Before the checkout below it is "nothing" by construction: a dry run never
# reaches a git write command, and a real cut has not made one yet either.
# PREVIOUS_REF and RELEASE_COMMIT are filled in once they exist.
PREVIOUS_REF=""
RELEASE_COMMIT=""
cleanup_hint() {
	if [ -z "$RELEASE_COMMIT" ]; then
		printf 'nothing was written; there is nothing to undo'
	else
		printf 'Nothing was pushed; undo the local state with: git checkout %s -q && git branch -D %s' \
			"$PREVIOUS_REF" "$BRANCH_NAME"
	fi
}

# ---------------------------------------------------------------------------
# The forge the pull request is opened on, derived from --remote's configured
# URL so it is the server the release branch is pushed to. Read with
# `git config` rather than `git remote get-url`, which applies insteadOf
# rewrites: those are a transport detail, and the configured URL is the one
# that names the forge. Checked, and the token proven against the forge API,
# before anything is fetched or written: a real cut that pushed its branch
# and only then found it could not open the pull request would leave a
# half-prepared release behind. A dry run checks the same.
# ---------------------------------------------------------------------------

REMOTE_URL=$($GIT config --get "remote.$REMOTE.url") || die "no git remote named '$REMOTE'"
FORGE_REPO=$(forge_repo_url "$REMOTE_URL")
[ -n "$FORGE_REPO" ] ||
	die "remote '$REMOTE' ($REMOTE_URL) names no forge repository -- it must be an ssh://, scp-like or http(s):// URL ending in <owner>/<repo>"
FORGE_BASE=${FORGE_REPO%/*/*}
FORGE_API="$FORGE_BASE/api/v1/repos/${FORGE_REPO#"$FORGE_BASE"/}"
[ -n "${FORGE_TOKEN:-}" ] ||
	die "FORGE_TOKEN is not set -- the release pull request is opened on $FORGE_REPO as the project agent"

FORGE_RESPONSE=$(mktemp) || die "could not create a scratch file for forge API responses"
SCRATCH_DIRS+=("$FORGE_RESPONSE")

# forge_api METHOD PATH [BODY] calls the repository's forge API and prints the
# HTTP status; the response body is left in $FORGE_RESPONSE. The token reaches
# curl as a header read from a file descriptor, never on its command line.
forge_api() {
	$CURL -sS -o "$FORGE_RESPONSE" -w '%{http_code}' -X "$1" \
		-H @<(printf 'Authorization: token %s\n' "$FORGE_TOKEN") \
		-H 'Content-Type: application/json' \
		${3:+--data-binary "$3"} "$FORGE_API$2"
}

code=$(forge_api GET "") || code=000
[ "$code" = 200 ] ||
	die "cannot read $FORGE_REPO through the forge API (HTTP $code) -- check FORGE_TOKEN and the '$REMOTE' remote"

# ---------------------------------------------------------------------------
# Fetch the tip this release is cut from. Read from THIS, never from whatever
# the operator happens to have checked out: a stale local main is exactly the
# TOCTOU class go-xkms#211 asks to make unrepresentable, and reading through a
# fetch answers "what is on the remote right now" instead of "what did I last
# happen to pull".
# ---------------------------------------------------------------------------

printf 'release-alpha: fetching %s/%s...\n' "$REMOTE" "$RELEASE_BRANCH"
$GIT fetch --quiet "$REMOTE" "$RELEASE_BRANCH" ||
	die "could not fetch $RELEASE_BRANCH from $REMOTE"
REMOTE_TIP=$($GIT rev-parse FETCH_HEAD) ||
	die "could not resolve the fetched tip of $REMOTE/$RELEASE_BRANCH"
# Tags too: the tag-namespace checks below and the exported-API growth gate
# both need the CURRENT release's tag, and a local tag cache can be stale in
# exactly the way the branch fetch above exists to avoid for the branch.
$GIT fetch --quiet --tags "$REMOTE" ||
	die "could not fetch tags from $REMOTE"

if $GIT rev-parse -q --verify "refs/heads/$BRANCH_NAME" >/dev/null; then
	die "local branch '$BRANCH_NAME' already exists -- delete it (git branch -D $BRANCH_NAME) if a previous prepare run did not finish, or pick the next version"
fi
if $GIT ls-remote --exit-code --heads "$REMOTE" "$BRANCH_NAME" >/dev/null 2>&1; then
	die "'$BRANCH_NAME' already exists on $REMOTE -- a release is already prepared for $NEXT. Open its pull request instead of preparing a second one, or pick the next version"
fi

# READROOT is a read-only materialization of the fetched tip: every
# precondition below reads from it, never from "." -- which, before the
# checkout further down, is still whatever branch the operator started on.
READROOT=$(mktemp -d) || die "could not create a scratch directory for the fetched tip"
SCRATCH_DIRS+=("$READROOT")
$GIT archive --format=tar "$REMOTE_TIP" | (cd "$READROOT" && tar -xf -) ||
	die "could not materialize the fetched tip of $REMOTE/$RELEASE_BRANCH"

# ---------------------------------------------------------------------------
# Version validation: a closed checklist over a stated version.
# ---------------------------------------------------------------------------

[ -f "$READROOT/VERSION" ] || die "VERSION not found at the root of $REMOTE/$RELEASE_BRANCH"
CURRENT=v$(tr -d ' \t\n' <"$READROOT/VERSION")
is_alpha_semver "$CURRENT" ||
	die "$REMOTE/$RELEASE_BRANCH's VERSION file holds '${CURRENT#v}', which is not a X.Y.Z-alpha version"

version_gt "$NEXT" "$CURRENT" ||
	die "$NEXT is not greater than the current version $CURRENT on $REMOTE/$RELEASE_BRANCH. Pass the version to publish: make release-alpha VERSION=<X.Y.Z-alpha>"

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
# in none of them. Asked of the LOCAL tag store, which the fetch above just
# refreshed from the remote; scripts/release-tag.sh re-asserts this against
# the remote again at tag time, since this script never publishes a tag.
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

# The pin set is validated BEFORE anything is written, dry run or not. It used
# to be checked after the changelog assembly, so a tree with an inconsistent
# pin set was refused only once its .changelog entries had already been
# consumed and staged -- a refusal that left work behind.
require_pins_at "$READROOT" "$CURRENT" "before the rewrite" ||
	die "refusing to prepare a release from an inconsistent pin set on $REMOTE/$RELEASE_BRANCH"

printf 'release-alpha: %s -> %s (%d reciprocal pins, %d tags)\n' \
	"$CURRENT" "$NEXT" "${#PIN_EDGES[@]}" "${#TAG_NAMESPACES[@]}"

# ---------------------------------------------------------------------------
# Exported-API growth gate (go-xkms#419/#421). Refuses an effective PATCH
# bump that adds exported Go API in any published module since the CURRENT
# tag -- the exact defect that shipped nine new exported symbols in a PATCH
# release with no check to catch it.
#
# Gated on the DERIVED level (bump_level CURRENT NEXT), not on whether --bump
# was passed: --bump is optional, and `--version 0.9.5-alpha` with no --bump
# at all is just as much a patch as `--bump patch --version 0.9.5-alpha` is --
# the incident this closes shipped with no --bump given at all. When --bump
# IS given it has already been asserted to agree with --version above, so the
# derived level and the stated one can never disagree by the time this runs.
# ---------------------------------------------------------------------------

LEVEL=$(bump_level "$CURRENT" "$NEXT")
if [ "$LEVEL" = patch ] && $GIT rev-parse -q --verify "refs/tags/$CURRENT" >/dev/null; then
	OLDROOT=$(mktemp -d) || die "could not create a scratch directory for $CURRENT"
	SCRATCH_DIRS+=("$OLDROOT")
	$GIT archive --format=tar "$CURRENT" | (cd "$OLDROOT" && tar -xf -) ||
		die "could not materialize $CURRENT for the exported-API comparison"

	TOOLDIR=$(mktemp -d) || die "could not create a scratch directory for the exported-API tool"
	SCRATCH_DIRS+=("$TOOLDIR")
	GOWORK=off "$GO" build -o "$TOOLDIR/exportsurface" ./scripts/exportsurface ||
		die "could not build scripts/exportsurface -- the exported-API comparison cannot run"

	MODULE_ARGS=()
	for m in "${API_MODULES[@]}"; do MODULE_ARGS+=(--module "$m"); done
	GROWTH=$("$TOOLDIR/exportsurface" --old "$OLDROOT" --new "$READROOT" "${MODULE_ARGS[@]}") ||
		die "the exported-API comparison failed"
	ADDED=$(printf '%s\n' "$GROWTH" | grep '^+ ' || true)
	if [ -n "$ADDED" ]; then
		die "$NEXT is a PATCH on $CURRENT but adds exported Go API:$(printf '\n  %s' "$ADDED")
Pass --bump minor (and a minor --version) if this is meant to ship, or remove the additions"
	fi
fi

# ---------------------------------------------------------------------------
# The tree the rest of this script writes to. A real cut checks out a new
# branch from the fetched tip and writes to the working tree; a dry run writes
# to a scratch copy of READROOT and nothing else, so it leaves the operator's
# actual working tree and branch byte-identical however it exits -- which is
# why there is no restore trap here to get wrong.
# ---------------------------------------------------------------------------

WORK=.
if [ "$DRY_RUN" = 1 ]; then
	SCRATCH=$(mktemp -d) || die "could not create a scratch directory"
	SCRATCH_DIRS+=("$SCRATCH")
	for f in "${RELEASE_FILES[@]}"; do
		mkdir -p "$SCRATCH/$(dirname "$f")"
		cp "$READROOT/$f" "$SCRATCH/$f"
	done
	if [ -f "$READROOT/CHANGELOG.md" ]; then
		cp "$READROOT/CHANGELOG.md" "$SCRATCH/CHANGELOG.md" ||
			die "could not copy CHANGELOG.md into the scratch directory"
	fi
	if [ -d "$READROOT/.changelog/unreleased" ]; then
		mkdir -p "$SCRATCH/.changelog"
		cp -R "$READROOT/.changelog/unreleased" "$SCRATCH/.changelog/unreleased" ||
			die "could not copy .changelog/unreleased into the scratch directory"
	fi
	WORK=$SCRATCH
else
	PREVIOUS_REF=$($GIT symbolic-ref -q --short HEAD 2>/dev/null) || PREVIOUS_REF=$($GIT rev-parse HEAD)
	$GIT checkout -q -b "$BRANCH_NAME" "$REMOTE_TIP" ||
		die "could not create and check out $BRANCH_NAME from the fetched tip of $REMOTE/$RELEASE_BRANCH"
fi

# Fold any pending .changelog/unreleased entries into CHANGELOG.md under the
# section this cut is about to publish (#354). Two properties matter: entries
# written per-PR cannot collide with each other while open, and an entry can
# only ever land in the section of the release that actually ships it (#361's
# failure class). With no pending entries this is a no-op and the heading
# check below remains the arbiter, exactly as before.
if changelog_entries_pending "$WORK/.changelog/unreleased"; then
	bash scripts/changelog-assemble.sh --root "$WORK" "${NEXT#v}" || {
		[ "$DRY_RUN" = 1 ] && die "changelog-assemble failed; fix the entry files before preparing the release"
		die "changelog-assemble failed; fix the entry files before preparing the release. $(cleanup_hint)"
	}
	if [ "$DRY_RUN" = 0 ]; then
		$GIT add CHANGELOG.md .changelog/unreleased ||
			die "failed to stage the assembled changelog. $(cleanup_hint)"
	fi
fi

changelog_has_heading "$WORK/CHANGELOG.md" "${NEXT#v}" || {
	MSG="CHANGELOG.md has no '## [${NEXT#v}]' section beginning a line. Add it (or add .changelog/unreleased entries for the assembler) and commit -- the release workflow fails the tag without it, AFTER the module tags have been pushed and become permanent"
	[ "$DRY_RUN" = 1 ] && die "$MSG"
	die "$MSG. $(cleanup_hint)"
}

# ---------------------------------------------------------------------------
# The pin rewrite, shared by both the rehearsal and the real cut: $WORK is
# the scratch copy for a dry run and "." (now checked out at the fetched tip)
# for a real one.
# ---------------------------------------------------------------------------

printf '%s\n' "${NEXT#v}" >"$WORK/VERSION"
for edge in "${PIN_EDGES[@]}"; do
	rewrite_pin "$WORK" "${edge%%:*}" "${edge#*:}" "$CURRENT" "$NEXT"
done

require_pins_at "$WORK" "$NEXT" "after the rewrite" || {
	[ "$DRY_RUN" = 1 ] && die "the rehearsed rewrite did not move every pin -- a real release would have refused here too"
	die "the rewrite did not move every pin. $(cleanup_hint)"
}

# ---------------------------------------------------------------------------
# Rehearsal
# ---------------------------------------------------------------------------

if [ "$DRY_RUN" = 1 ]; then
	for f in "${RELEASE_FILES[@]}" CHANGELOG.md; do
		[ -f "$SCRATCH/$f" ] || continue
		diff -u --label "a/$f" --label "b/$f" "$READROOT/$f" "$SCRATCH/$f" || true
	done
	# The entry files a real cut would consume, named rather than diffed: they
	# are still on the fetched tip, so there is no deletion for `diff` to show.
	if [ -d "$READROOT/.changelog/unreleased" ]; then
		for f in "$READROOT/.changelog/unreleased"/*.md; do
			[ -f "$f" ] || continue
			base=${f##*/}
			case "$base" in README.md) continue ;; esac
			[ -f "$SCRATCH/.changelog/unreleased/$base" ] ||
				printf 'release-alpha: would remove .changelog/unreleased/%s\n' "$base"
		done
	fi
	printf 'release-alpha: DRY RUN -- would push %s to %s and open a pull request into %s:\n' \
		"$BRANCH_NAME" "$REMOTE" "$RELEASE_BRANCH"
	printf '  "%s" on %s\n' "$RELEASE_TITLE" "$FORGE_REPO"
	printf 'release-alpha: nothing was changed\n'
	exit 0
fi

# ---------------------------------------------------------------------------
# The release commit, the branch push and the pull request. NOTHING beyond
# this point is reachable from --dry-run.
# ---------------------------------------------------------------------------

$GIT add -- "${RELEASE_FILES[@]}" || die "could not stage the release files. $(cleanup_hint)"
$GIT commit -q -m "$RELEASE_TITLE" || die "the release commit failed. $(cleanup_hint)"
RELEASE_COMMIT=$($GIT rev-parse HEAD) || die "could not resolve the release commit"

$GIT push -u "$REMOTE" "$BRANCH_NAME" ||
	die "the branch push was refused, so nothing was published. The commit is still local on $BRANCH_NAME. $(cleanup_hint)"
printf 'release-alpha: pushed %s to %s at %s\n' "$BRANCH_NAME" "$REMOTE" "$RELEASE_COMMIT"

PR_REQUEST=$(printf '{"title":%s,"head":%s,"base":%s,"body":%s}' \
	"$(json_string "$RELEASE_TITLE")" "$(json_string "$BRANCH_NAME")" "$(json_string "$RELEASE_BRANCH")" \
	"$(json_string "Prepared by scripts/release-alpha.sh. Once this is reviewed and merged, run: make release-tag VERSION=${NEXT#v}")")
code=$(forge_api POST /pulls "$PR_REQUEST") || code=000
[ "$code" = 201 ] ||
	die "the forge refused to open the pull request (HTTP $code) although $BRANCH_NAME is pushed. Open it by hand, titled '$RELEASE_TITLE': $FORGE_REPO/compare/$RELEASE_BRANCH...$BRANCH_NAME"

# The response's only html_url under /pulls/ is the pull request's own; the
# user and repository objects it embeds carry html_urls of their own too.
PR_URL=$(grep -oE '"html_url":"[^"]*/pulls/[0-9]+"' "$FORGE_RESPONSE") || PR_URL=""
PR_URL=${PR_URL#*:\"}
PR_URL=${PR_URL%\"}
printf 'release-alpha: opened pull request "%s": %s\n' "$RELEASE_TITLE" "${PR_URL:-$FORGE_REPO/pulls}"
printf 'release-alpha: once that pull request is reviewed and merged, run: make release-tag VERSION=%s\n' "${NEXT#v}"
