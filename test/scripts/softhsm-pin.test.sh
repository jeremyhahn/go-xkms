#!/usr/bin/env bash
#
# Tests for the SoftHSM pin (go-xkms#1418).
#
# scripts/build-softhsm.sh is the one place SoftHSM's version and archive
# checksum are pinned. These tests prove the script refuses an archive that
# does not hash to the pin before anything is extracted or built, and that no
# image, compose file, workflow or script in the repository installs the
# distribution's SoftHSM package (2.6.1, which answers an AES-GCM tag mismatch
# with the ambiguous CKR_GENERAL_ERROR) instead of building the pinned
# release. Nothing here downloads or compiles SoftHSM; every image build does
# that, and the PKCS#11 suites run against the result.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/scripts/build-softhsm.sh"
set +e
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n    want: %s\n    got:  %s\n' "$1" "$2" "$3" >&2; }
eq() { [ "$2" = "$3" ] && ok "$1" || no "$1" "$2" "$3"; }
section() { printf '\n%s\n' "$1"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# A PATH whose tar, make and curl only record that they were called, so a
# test can prove the script stopped before extracting, building or fetching.
FAKEBIN="$WORK/bin"
mkdir -p "$FAKEBIN"
for tool in tar make curl wget; do
	cat >"$FAKEBIN/$tool" <<EOF
#!/bin/sh
echo "$tool" >>"$WORK/called"
exit 0
EOF
	chmod +x "$FAKEBIN/$tool"
done

pinned=$(sed -n 's/^SOFTHSM_SHA256=//p' "$SCRIPT")
version=$(sed -n 's/^SOFTHSM_VERSION=//p' "$SCRIPT")

# is_sha256 VALUE -- exactly 64 lowercase hex digits, nothing else.
is_sha256() { [[ "$1" =~ ^[0-9a-f]{64}$ ]]; }

section "the pin"
eq "the pinned version is at least 2.7.0" "2.7.0" "$(printf '%s\n2.7.0\n' "$version" | sort -V | head -1)"
if is_sha256 "$pinned"; then ok "the pinned checksum is a SHA-256 digest"; else no "the pinned checksum is a SHA-256 digest" "64 hex digits" "$pinned"; fi
if is_sha256 "${pinned:0:4}z${pinned:5}"; then no "a non-hex digit anywhere is not a digest" "rejected" "accepted"; else ok "a non-hex digit anywhere is not a digest"; fi
if is_sha256 "${pinned}0"; then no "a 65-digit value is not a digest" "rejected" "accepted"; else ok "a 65-digit value is not a digest"; fi

section "an archive that does not match the pin is refused before anything runs"
printf 'not the SoftHSM release\n' >"$WORK/bogus.tar.gz"
: >"$WORK/called"
out=$(PATH="$FAKEBIN:$PATH" SOFTHSM_ARCHIVE="$WORK/bogus.tar.gz" sh "$SCRIPT" 2>&1)
rc=$?
eq "exit 1" 1 "$rc"
case "$out" in
*"pinned ${pinned}"*) ok "the error names the pinned checksum" ;;
*) no "the error names the pinned checksum" "pinned ${pinned}" "$out" ;;
esac
eq "nothing was fetched, extracted or built" "" "$(cat "$WORK/called")"

section "usage"
out=$(sh "$SCRIPT" /usr /extra 2>&1)
rc=$?
eq "two arguments is usage, exit 2" 2 "$rc"

section "no distribution SoftHSM package is installed anywhere"
# A package token: softhsm2, libsofthsm2 or libsofthsm2-dev, optionally with
# an :arch suffix, standing alone (softhsm2-util, softhsm2.conf and paths do
# not match). Comment lines are ignored.
pkg='(^|[[:space:]"'\''=])(lib)?softhsm2(-dev)?(:[a-z0-9]+)?([[:space:]\\"'\'']|$)'
hits=$(cd "$ROOT" && git ls-files -- 'Dockerfile*' '*/Dockerfile*' '*.yml' '*.yaml' '*.sh' 'Makefile' '*/Makefile' |
	grep -v '^test/scripts/softhsm-pin.test.sh$' |
	while read -r f; do
		grep -nE "$pkg" "$f" | grep -vE '^[0-9]+:[[:space:]]*#' | sed "s|^|$f:|"
	done)
eq "no install names softhsm2/libsofthsm2" "" "$hits"

# Alpine's and other distributions' package is plain "softhsm", a word that
# also names users, groups and directories, so it is only an install when it
# is a package token in a package-manager command. Continuation lines are
# joined first, so a package on its own line of a multi-line RUN is caught.
installs='(apk add|apt-get install|apt install|dnf install|yum install|apt-deps\.sh|EXTRA_APT_PACKAGES)'
alpine='(^|[[:space:]"'\''=])softhsm(-dev)?([[:space:]\\"'\'']|$)'
hits=$(cd "$ROOT" && git ls-files -- 'Dockerfile*' '*/Dockerfile*' '*.yml' '*.yaml' '*.sh' 'Makefile' '*/Makefile' |
	grep -v '^test/scripts/softhsm-pin.test.sh$' |
	while read -r f; do
		awk '/^[[:space:]]*#/ { next } { line = line $0 } /\\$/ { sub(/\\$/, " ", line); next } { print FILENAME ": " line; line = "" }' "$f"
	done | grep -E "$installs" | grep -E "$alpine")
eq "no package manager installs softhsm" "" "$hits"

section "every image that carries SoftHSM builds the pinned release"
missing=$(cd "$ROOT" && git ls-files -- 'Dockerfile*' '*/Dockerfile*' |
	while read -r f; do
		if grep -vE '^[[:space:]]*#' "$f" | grep -qi 'softhsm' && ! grep -q 'build-softhsm.sh' "$f"; then
			echo "$f"
		fi
	done)
eq "no Dockerfile uses SoftHSM without scripts/build-softhsm.sh" "" "$missing"

section "every workflow that initializes a token builds the pinned release"
# A workflow that runs its commands in the toolchain image
# (scripts/in-toolchain-image.sh) gets SoftHSM from that image, which the
# Dockerfile check above holds to the pin.
missing=$(cd "$ROOT" && git ls-files -- '.github/workflows/*.yml' |
	while read -r f; do
		if grep -q 'softhsm2-util' "$f" && ! grep -qE 'scripts/(build-softhsm|in-toolchain-image)\.sh' "$f"; then
			echo "$f"
		fi
	done)
eq "no workflow runs softhsm2-util outside the pinned release" "" "$missing"

printf '\npassed %d, failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
