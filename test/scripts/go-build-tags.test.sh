#!/usr/bin/env bash
#
# Tests that every target ci-template calls reads GO_BUILD_TAGS (go-xkms#1603).
# The template runs `make lint|build|coverage|security|integration-test
# GO_BUILD_TAGS='a b'`; a target that ignores the variable never builds, lints
# or covers the code behind those tags.
#
# Each target is dry-run (`make -n`) and every build-tag list in its output is
# compared:
#   - unset and empty GO_BUILD_TAGS print the same commands;
#   - with GO_BUILD_TAGS set, every list carries its tags, comma-joined with
#     no duplicates, and is the list the target already used plus those tags.
# Lines that call $(MAKE) still execute under -n, so docker, go and the other
# tools they reach are no-op stand-ins on PATH: nothing is built or started.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
set +e
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n    want: %s\n    got:  %s\n' "$1" "$2" "$3" >&2; }
eq() { [ "$2" = "$3" ] && ok "$1" || no "$1" "$2" "$3"; }
section() { printf '\n%s\n' "$1"; }

# The caller's make (make test) must not leak its flags or its own
# GO_BUILD_TAGS into the runs below.
unset MAKEFLAGS MFLAGS MAKELEVEL GO_BUILD_TAGS XKMS_DEVCONTAINER LINT_CI

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# No-op stand-ins. `go env GOPATH` answers $WORK, so the actionlint recipe's
# fallback $(go env GOPATH)/bin/actionlint is the stand-in too.
mkdir -p "$WORK/bin"
for tool in docker go actionlint golangci-lint gosec govulncheck trivy npm wails sudo; do
	printf '#!/bin/sh\n[ "$1 $2" = "env GOPATH" ] && echo "%s"\nexit 0\n' "$WORK" >"$WORK/bin/$tool"
	chmod +x "$WORK/bin/$tool"
done
export PATH="$WORK/bin:$PATH"

PROBE=gbt_probe
# codec_json is a tag every target already uses: adding it must not repeat it.
EXTRA="$PROBE codec_json"

# dry_run TARGET VAR=VALUE... prints `make -n TARGET`. BUILD_DATE is pinned:
# it is the clock, so two runs a second apart would differ in -ldflags.
dry_run() {
	local target="$1"
	shift
	make -n -k --no-print-directory -C "$ROOT" "$target" BUILD_DATE=gbt-date "$@" 2>/dev/null
}

# tag_values prints, one per line, every build-tag list in a dry run: each
# -tags/--build-tags value, plus the tags="..." assignments and
# `for tags in "..."` lists the lint loops hand to --build-tags "$tags". A flag
# whose value is a shell variable is skipped: its values are the assignments.
# `wails generate module` is skipped too: check-wailsjs regenerates the
# bindings under wails.json's tags to compare them with the committed copy, so
# extra tags there would only make that comparison fail.
tag_values() {
	local match value
	grep -v 'wails.* generate module' |
		grep -oE -- "(-tags|--build-tags)(=| )(\"[^\"]*\"|'[^']*'|[^ \"';)]*)|tags=\"[^\"]*\"|for tags in( \"[^\"]*\")+" |
		while IFS= read -r match; do
			if [[ $match == "for tags in "* ]]; then
				match=${match#for tags in }
				while [[ $match =~ ^\ ?\"([^\"]*)\"(.*)$ ]]; do
					echo "${BASH_REMATCH[1]}"
					match=${BASH_REMATCH[2]}
				done
				continue
			fi
			value=${match#-tags}
			value=${value#--build-tags}
			value=${value#tags=}
			value=${value#[= ]}
			value=${value#[\"\']}
			value=${value%[\"\']}
			[[ $value == *'$'* ]] || echo "$value"
		done
}

# tag_set TAGS... prints the distinct tags of space or comma lists, sorted.
tag_set() {
	printf '%s\n' "$@" | tr ', ' '\n\n' | sed '/^$/d' | sort -u | tr '\n' ' '
}

# check_target NAME TARGET VAR=VALUE... runs the checks for one target.
check_target() {
	local name="$1" target="$2"
	shift 2
	local unset_out empty_out
	unset_out=$(dry_run "$target" "$@")
	empty_out=$(dry_run "$target" "$@" GO_BUILD_TAGS=)
	eq "$name: empty GO_BUILD_TAGS prints what unset prints" "" \
		"$(diff <(echo "$unset_out") <(echo "$empty_out") | head -4 | cut -c1-200)"

	local -a base tagged
	mapfile -t base < <(tag_values <<<"$unset_out")
	mapfile -t tagged < <(dry_run "$target" "$@" "GO_BUILD_TAGS=$EXTRA" | tag_values)
	if [ "${#tagged[@]}" -eq 0 ]; then
		no "$name: dry run passes build tags" "at least one -tags list" "none"
		return
	fi

	local value bad="" i=0 extra_set want
	extra_set=$(tag_set $EXTRA)
	for value in "${tagged[@]}"; do
		[[ ",$value," == *",$PROBE,"* ]] || bad+=" [$value: no $PROBE]"
		[[ $value != *' '* ]] || bad+=" [$value: not comma-joined]"
		[ "$(tr ',' '\n' <<<"$value" | sort | uniq -d)" = "" ] || bad+=" [$value: duplicate tag]"
		# Each list is the next list the target already used plus EXTRA, or
		# EXTRA alone where the command passed no -tags before.
		want=$(tag_set "${base[i]-}" $EXTRA)
		if [ "$i" -lt "${#base[@]}" ] && [ "$(tag_set "$value")" = "$want" ]; then
			i=$((i + 1))
		elif [ "$(tag_set "$value")" != "$extra_set" ]; then
			bad+=" [$value: is not '${base[i]-}' plus $EXTRA]"
		fi
	done
	[ "$i" -eq "${#base[@]}" ] || bad+=" [only $i of ${#base[@]} existing lists carry GO_BUILD_TAGS]"
	eq "$name: every -tags list adds GO_BUILD_TAGS (${#tagged[@]} lists)" "" "$bad"
}

section "go_tags joins GO_BUILD_TAGS"
FN_MK="$WORK/fn.mk"
printf 'include %s/scripts/go-build-tags.mk\nt: ; @echo "[$(call go_tags,$(T))] [$(call go_tags_flag,$(T))]"\n' "$ROOT" >"$FN_MK"
fn() { make -s --no-print-directory -f "$FN_MK" t "$@"; }
eq "unset leaves the list as given" "[a b  c] [ -tags=a b  c]" "$(fn 'T=a b  c')"
eq "empty leaves the list as given" "[a,b] [ -tags=a,b]" "$(fn T=a,b GO_BUILD_TAGS=)"
eq "unset and no list give no flag" "[] []" "$(fn T=)"
eq "space list joined with commas, no duplicates" "[a,b,c,z] [ -tags=a,b,c,z]" "$(fn 'T=a b c' 'GO_BUILD_TAGS=b z a')"
eq "comma list and comma GO_BUILD_TAGS" "[a,b,z,q] [ -tags=a,b,z,q]" "$(fn T=a,b GO_BUILD_TAGS=z,q)"
eq "no list of its own" "[z,q] [ -tags=z,q]" "$(fn T= 'GO_BUILD_TAGS=z q')"

section "ci-template targets read GO_BUILD_TAGS"
check_target "lint" lint
check_target "build (toolchain image)" build XKMS_NATIVE_BUILD=1
check_target "build (builder images)" build XKMS_NATIVE_BUILD=0
check_target "coverage" coverage
check_target "security" security
check_target "integration-test" integration-test

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
exit $?
