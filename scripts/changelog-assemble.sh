#!/usr/bin/env bash
#
# changelog-assemble.sh -- fold .changelog/unreleased/*.md into CHANGELOG.md
# under a new version heading, and remove the assembled files.
#
# Usage: changelog-assemble.sh <version-without-v> [<date>]
#
# Entries are files named <section>-<slug>.md where <section> selects the
# `###` heading (security|added|changed|deprecated|removed|fixed). The file
# body is spliced verbatim. Sections appear in the fixed order below; within a
# section, entries sort by file name, so ordering is deterministic.
#
# With no entry files the script exits 0 without touching CHANGELOG.md: a
# release cut from a tree whose entries were already assembled (or that
# genuinely has none) is not an error here -- the release gate's heading
# check remains the arbiter.
#
# Sourcing with CHANGELOG_ASSEMBLE_LIB=1 defines the functions and returns,
# for the unit tests in test/scripts/changelog-assemble.test.sh.
set -euo pipefail

SECTION_ORDER=(security added changed deprecated removed fixed)

section_heading() {
	case "$1" in
	security)   printf '### Security'   ;;
	added)      printf '### Added'      ;;
	changed)    printf '### Changed'    ;;
	deprecated) printf '### Deprecated' ;;
	removed)    printf '### Removed'    ;;
	fixed)      printf '### Fixed'      ;;
	*) return 1 ;;
	esac
}

# entry_section <path> -> section name from the file name, or failure for a
# name that matches no known section (a typo must fail the cut loudly, not
# silently drop an entry from the release notes).
entry_section() {
	local base
	base=$(basename "$1")
	local sec="${base%%-*}"
	section_heading "$sec" >/dev/null 2>&1 || return 1
	printf '%s' "$sec"
}

# assemble <changelog> <entries-dir> <version> <date>
# Builds the new section text and splices it directly beneath the
# `## [Unreleased]` line. Prints the list of assembled files, one per line.
assemble() {
	local changelog="$1" dir="$2" version="$3" date="$4"

	[ -f "$changelog" ] || { echo "changelog-assemble: $changelog not found" >&2; return 1; }
	grep -q '^## \[Unreleased\]' "$changelog" || {
		echo "changelog-assemble: $changelog has no ## [Unreleased] heading" >&2; return 1; }

	local files=()
	if [ -d "$dir" ]; then
		while IFS= read -r f; do files+=("$f"); done \
			< <(find "$dir" -maxdepth 1 -name '*.md' ! -name 'README.md' | LC_ALL=C sort)
	fi
	if [ ${#files[@]} -eq 0 ]; then
		return 0
	fi

	local f sec
	for f in "${files[@]}"; do
		entry_section "$f" >/dev/null || {
			echo "changelog-assemble: $(basename "$f") names no known section (want <section>-<slug>.md, section in: ${SECTION_ORDER[*]})" >&2
			return 1
		}
	done

	local body="## [$version] - $date"
	for sec in "${SECTION_ORDER[@]}"; do
		local sec_body=""
		for f in "${files[@]}"; do
			[ "$(entry_section "$f")" = "$sec" ] || continue
			sec_body+=$'\n'"$(cat "$f")"
		done
		if [ -n "$sec_body" ]; then
			body+=$'\n\n'"$(section_heading "$sec")"$'\n'"$sec_body"
		fi
	done

	# The assembled block reaches awk through the ENVIRONMENT, not `-v`: `-v`
	# processes C-style escapes, so an entry containing a literal backslash
	# (code snippets, markdown escapes like `\*`) would be silently mangled,
	# breaking the "spliced verbatim" contract. ENVIRON is passed byte-for-byte.
	local tmp
	tmp=$(mktemp) || return 1
	CHANGELOG_BLOCK="$body" awk '
		BEGIN { block = ENVIRON["CHANGELOG_BLOCK"] }
		{ print }
		/^## \[Unreleased\]/ && !done { print ""; print block; done = 1 }
	' "$changelog" > "$tmp" || { rm -f "$tmp"; return 1; }
	mv "$tmp" "$changelog" || return 1

	printf '%s\n' "${files[@]}"
}

if [ "${CHANGELOG_ASSEMBLE_LIB:-0}" = 1 ]; then
	return 0 2>/dev/null || exit 0
fi

VERSION="${1:-}"
[ -n "$VERSION" ] || { echo "usage: changelog-assemble.sh <version-without-v> [<date>]" >&2; exit 2; }
DATE="${2:-$(date +%Y-%m-%d)}"
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

assembled=$(assemble "$ROOT/CHANGELOG.md" "$ROOT/.changelog/unreleased" "$VERSION" "$DATE") || exit 1
[ -n "$assembled" ] || { echo "changelog-assemble: no entries to assemble"; exit 0; }
printf '%s\n' "$assembled" | while IFS= read -r f; do rm -f "$f"; done
echo "changelog-assemble: assembled $(printf '%s\n' "$assembled" | wc -l | tr -d ' ') entries into [$VERSION]"
