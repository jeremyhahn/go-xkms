#!/usr/bin/env bash
#
# Tests that the root Makefile builds xkey with exactly the tags xkey's own
# Makefile selects for the same WITH_* toggles: XKEY_BUILD_TAGS must forward
# every toggle to the `make -C xkey print-build-tags` sub-make. Each case is
# checked twice: with the toggles on the command line, and with them as
# assignments in a makefile that includes the root one, which a $(shell)
# child never inherits. The second form is also how a GNU make before 4.4
# treats command-line variables, which it does not export to $(shell).
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
set +e
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n    want: %s\n    got:  %s\n' "$1" "$2" "$3" >&2; }
eq() { [ "$2" = "$3" ] && ok "$1" || no "$1" "$2" "$3"; }
section() { printf '\n%s\n' "$1"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# normalize collapses the whitespace runs the tag lists carry.
normalize() { tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//'; }

# xkey_tags TOGGLE... prints the tags xkey's Makefile selects on its own.
xkey_tags() {
	make -s --no-print-directory -C "$ROOT/xkey" "$@" print-build-tags | normalize
}

# root_makefile ASSIGNMENT... writes a makefile that sets ASSIGNMENTs, includes
# the root Makefile and prints its XKEY_BUILD_TAGS, and prints its path.
root_makefile() {
	local mk
	mk=$(mktemp "$WORK/root-XXXXXX.mk")
	for assignment in "$@"; do
		printf '%s := %s\n' "${assignment%%=*}" "${assignment#*=}" >>"$mk"
	done
	printf 'include %s/Makefile\nprint-xkey-tags: ; @echo $(XKEY_BUILD_TAGS)\n' "$ROOT" >>"$mk"
	echo "$mk"
}

# root_tags_cmdline TOGGLE... prints the root's XKEY_BUILD_TAGS with the
# toggles on the command line.
root_tags_cmdline() {
	make -s --no-print-directory -C "$ROOT" -f "$(root_makefile)" "$@" print-xkey-tags | normalize
}

# root_tags_assigned TOGGLE... prints the root's XKEY_BUILD_TAGS with the
# toggles set as makefile assignments rather than command-line variables.
root_tags_assigned() {
	make -s --no-print-directory -C "$ROOT" -f "$(root_makefile "$@")" print-xkey-tags | normalize
}

check() {
	local name="$1"
	shift
	local want
	want=$(xkey_tags "$@")
	eq "$name (command line)" "$want" "$(root_tags_cmdline "$@")"
	eq "$name (makefile assignment)" "$want" "$(root_tags_assigned "$@")"
}

section "root xkey tags match xkey's own selection"
check "defaults"
check "PKCS#11 and the AWS umbrella off" WITH_PKCS11=0 WITH_AWS=0
check "GCP umbrella off" WITH_GCP=0
check "Azure umbrella and MinIO off" WITH_AZURE=0 WITH_MINIO=0
check "individual object-storage toggles off" WITH_AWS_S3=0 WITH_GLACIER=0 WITH_GCP_STORAGE=0

section "opt-outs actually drop the tags"
TAGS=$(root_tags_assigned WITH_PKCS11=0 WITH_AWS=0)
for tag in pkcs11 awss3 glacier; do
	eq "WITH_PKCS11=0 WITH_AWS=0 drops $tag" "0" "$(tr ' ' '\n' <<<"$TAGS" | grep -cx "$tag")"
done

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
exit $?
