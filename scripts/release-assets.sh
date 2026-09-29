#!/usr/bin/env bash
#
# release-assets.sh — the release workflow's view of a Gitea release's assets.
#
# Usage:
#	scripts/release-assets.sh list
#	scripts/release-assets.sh expected        VERSION
#	scripts/release-assets.sh verify          VERSION
#	scripts/release-assets.sh verify-complete VERSION
#	scripts/release-assets.sh download        DIR [GLOB]
#	scripts/release-assets.sh upload          FILE...
#
# Environment (all required except DRY_RUN):
#	RELEASE_API   Gitea API root, e.g. http://host:3001/api/v1 (github.api_url)
#	RELEASE_REPO  owner/repo (github.repository)
#	RELEASE_TAG   the tag whose release is addressed, e.g. v0.11.0-alpha
#	RELEASE_TOKEN a token allowed to read and write that release's assets
#	DRY_RUN       when 1, upload prints its decisions and changes nothing
#
# Why this exists (#447). The generic release action deletes an existing asset
# and re-uploads it, and Gitea answers the re-upload with 404, so a workflow
# re-run failed on every leg that had ALREADY succeeded while succeeding on
# the leg that had flaked. One flaked matrix leg therefore cost a release its
# master checksums for good, because a tag cannot be re-cut. Here an upload is
# idempotent: an asset that is already present with the same SHA-256 is left
# alone, one with a different digest is replaced, one that is absent is added.
# `verify` states the complete asset set the build matrix produces, so the
# checksums job can fail on what is genuinely missing rather than on how many
# runs it took to get there.
#
# Every command is a closed question against the release as it IS, read
# through the API, never against what this run happens to have built.
set -euo pipefail

usage() { sed -n '3,17p' "$0" >&2; exit 2; }

need_env() {
	local v
	for v in RELEASE_API RELEASE_REPO RELEASE_TAG RELEASE_TOKEN; do
		if [ -z "${!v:-}" ]; then
			echo "release-assets: $v is not set" >&2
			exit 2
		fi
	done
}

api() {
	# api METHOD PATH [curl args...] — authenticated call against RELEASE_API.
	local method="$1" path="$2"; shift 2
	curl -sS --fail-with-body -X "$method" \
		-H "Authorization: token ${RELEASE_TOKEN}" \
		"${RELEASE_API}${path}" "$@"
}

release_json() {
	api GET "/repos/${RELEASE_REPO}/releases/tags/${RELEASE_TAG}"
}

# release_assets prints one line per asset: id TAB name TAB size TAB url
release_assets() {
	release_json | python3 -c '
import json, sys
r = json.load(sys.stdin)
for a in sorted(r.get("assets", []), key=lambda a: a["name"]):
    print("\t".join(str(a[k]) for k in ("id", "name", "size", "browser_download_url")))
'
}

release_id() {
	release_json | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])'
}

# expected VERSION — the asset names the build matrix produces. This is the
# one statement of the matrix outside the workflow; keep it in step with the
# `include:` list of build-binaries in .github/workflows/release.yml.
cmd_expected() {
	local version="$1" arch binary variant
	for arch in amd64 arm64; do
		for binary in xkmsctl xkmsd; do
			for variant in "" "-fips"; do
				echo "${binary}-${version}-linux-${arch}${variant}"
				echo "${binary}-${version}-linux-${arch}${variant}.sha256"
			done
		done
		echo "xkey-${version}-linux-${arch}"
		echo "xkey-${version}-linux-${arch}.sha256"
	done
}

cmd_list() {
	need_env
	release_assets
}

# verify VERSION — exit 1 naming every expected asset the release lacks.
cmd_verify() {
	need_env
	local version="$1" missing=0 name
	local present
	present="$(release_assets | cut -f2)"
	while read -r name; do
		if ! grep -qx -- "$name" <<<"$present"; then
			echo "missing: $name"
			missing=$((missing + 1))
		fi
	done < <(cmd_expected "$version")
	if [ "$missing" -gt 0 ]; then
		echo "release ${RELEASE_TAG} is missing ${missing} asset(s)" >&2
		return 1
	fi
	echo "release ${RELEASE_TAG}: all $(cmd_expected "$version" | wc -l) expected assets present"
}

# verify-complete VERSION — the final-gate form of `verify` (go-xkms#1026): a
# release is complete only when it carries EXACTLY the build matrix's assets
# PLUS the master `checksums.txt` create-checksums adds afterward -- no
# fewer (a flaked leg) and no more (a stray or misnamed upload). `verify`
# itself cannot require checksums.txt: create-checksums calls `verify` BEFORE
# checksums.txt exists, to decide whether it is safe to create it at all, so
# baking that requirement into `cmd_expected` would make that call fail
# every single run. This is deliberately the one caller that adds it.
cmd_verify_complete() {
	need_env
	local version="$1" name rc=0
	local present expected
	present="$(release_assets | cut -f2 | sort)"
	expected="$( { cmd_expected "$version"; echo "checksums.txt"; } | sort)"
	while IFS= read -r name; do
		[ -n "$name" ] || continue
		if ! grep -qx -- "$name" <<<"$present"; then
			echo "missing: $name"
			rc=1
		fi
	done <<<"$expected"
	while IFS= read -r name; do
		[ -n "$name" ] || continue
		if ! grep -qx -- "$name" <<<"$expected"; then
			echo "unexpected: $name"
			rc=1
		fi
	done <<<"$present"
	local want have
	want="$(wc -l <<<"$expected" | tr -d ' ')"
	have="$(wc -l <<<"$present" | tr -d ' ')"
	if [ "$rc" -ne 0 ]; then
		echo "release ${RELEASE_TAG}: ${have} asset(s) present, ${want} expected (name mismatch listed above)" >&2
		return 1
	fi
	if [ "$have" != "$want" ]; then
		# Every name matched 1:1 above, so equal sets with unequal counts
		# means a duplicate name reached the API twice -- state that
		# explicitly rather than let it pass silently.
		echo "release ${RELEASE_TAG}: ${have} asset(s) present but names are a 1:1 match against ${want} expected -- duplicate asset name" >&2
		return 1
	fi
	echo "release ${RELEASE_TAG}: complete -- exactly the expected ${want} asset(s) (matrix + checksums.txt), no extras"
}

download_asset() {
	# download_asset URL DEST — the download URL honours the token header.
	local url="$1" dest="$2"
	curl -sS --fail -L -H "Authorization: token ${RELEASE_TOKEN}" -o "$dest" "$url"
}

# download DIR [GLOB] — every asset (or those matching GLOB) into DIR.
cmd_download() {
	need_env
	local dir="$1" glob="${2:-*}" id name size url
	mkdir -p "$dir"
	while IFS=$'\t' read -r id name size url; do
		# shellcheck disable=SC2254
		case "$name" in
		$glob) download_asset "$url" "${dir}/${name}"; echo "downloaded ${name} (${size} bytes)" ;;
		esac
	done < <(release_assets)
}

sha256_of() { sha256sum "$1" | cut -d' ' -f1; }

# plan_upload FILE — prints one of: skip | mismatch ASSET_ID | add
plan_upload() {
	local file="$1" name id aname size url tmp
	name="$(basename "$file")"
	while IFS=$'\t' read -r id aname size url; do
		[ "$aname" = "$name" ] || continue
		tmp="$(mktemp)"
		download_asset "$url" "$tmp"
		if [ "$(sha256_of "$tmp")" = "$(sha256_of "$file")" ]; then
			rm -f "$tmp"; echo "skip"; return 0
		fi
		rm -f "$tmp"; echo "mismatch $id"; return 0
	done < <(release_assets)
	echo "add"
}

# upload FILE... — idempotent; see the header.
cmd_upload() {
	need_env
	local rid file name plan action id
	rid="$(release_id)"
	for file in "$@"; do
		[ -f "$file" ] || { echo "release-assets: no such file: $file" >&2; return 1; }
		name="$(basename "$file")"
		plan="$(plan_upload "$file")"
		action="${plan%% *}"
		case "$action" in
		skip)
			echo "${name}: already present with the same SHA-256, skipped" ;;
		mismatch)
			id="${plan#mismatch }"
			echo "ERROR: ${name}: asset ${id} exists with a different SHA-256" >&2
			echo "ERROR: Release assets must be idempotent. Do not overwrite existing artifacts." >&2
			echo "ERROR: If this is intentional, manually delete the asset and retry." >&2
			return 1 ;;
		add)
			echo "${name}: absent, uploading"
			if [ "${DRY_RUN:-0}" != 1 ]; then
				api POST "/repos/${RELEASE_REPO}/releases/${rid}/assets?name=${name}" -F "attachment=@${file}" >/dev/null
			fi ;;
		esac
	done
}

[ $# -ge 1 ] || usage
cmd="$1"; shift
case "$cmd" in
list)            cmd_list "$@" ;;
expected)        [ $# -eq 1 ] || usage; cmd_expected "$@" ;;
verify)          [ $# -eq 1 ] || usage; cmd_verify "$@" ;;
verify-complete) [ $# -eq 1 ] || usage; cmd_verify_complete "$@" ;;
download)        [ $# -ge 1 ] || usage; cmd_download "$@" ;;
upload)          [ $# -ge 1 ] || usage; cmd_upload "$@" ;;
*) usage ;;
esac
