#!/usr/bin/env bash
#
# Tests for scripts/softhsm-lib.sh (go-xkms#1420, ruling 991 (3)).
#
# The helper prints the libsofthsm2.so the PKCS#11 suites load: the system
# module when the installed SoftHSM is 2.7.0 or newer (the minimum that
# reports PKCS#11 tamper, #1418), otherwise the pinned release built by
# scripts/build-softhsm.sh into a user cache, built once and reused. Nothing
# here downloads or compiles SoftHSM: softhsm2-util and the build script are
# stubs that only record they were called.
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="$ROOT/scripts/softhsm-lib.sh"
set +e
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n    want: %s\n    got:  %s\n' "$1" "$2" "$3" >&2; }
eq() { [ "$2" = "$3" ] && ok "$1" || no "$1" "$2" "$3"; }
section() { printf '\n%s\n' "$1"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# A system SoftHSM whose softhsm2-util reports $STUB_VERSION, with its module
# where the Debian layout puts it relative to the binary.
SYS="$WORK/sys"
mkdir -p "$SYS/bin" "$SYS/lib/softhsm"
: >"$SYS/lib/softhsm/libsofthsm2.so"
cat >"$SYS/bin/softhsm2-util" <<'EOF'
#!/bin/sh
echo "$STUB_VERSION"
EOF
chmod +x "$SYS/bin/softhsm2-util"

# A build script that records each call and installs a stub 2.7.0 under
# DESTDIR/PREFIX the way scripts/build-softhsm.sh lays it out.
BUILD="$WORK/build-softhsm.sh"
cat >"$BUILD" <<EOF
#!/bin/sh
SOFTHSM_VERSION=2.7.0
echo build >>"$WORK/built"
mkdir -p "\${DESTDIR}\$1/bin" "\${DESTDIR}\$1/lib/softhsm"
printf '#!/bin/sh\necho 2.7.0\n' >"\${DESTDIR}\$1/bin/softhsm2-util"
chmod +x "\${DESTDIR}\$1/bin/softhsm2-util"
: >"\${DESTDIR}\$1/lib/softhsm/libsofthsm2.so"
echo "SoftHSM 2.7.0 installed under \${DESTDIR}\$1"
EOF
chmod +x "$BUILD"

CACHE="$WORK/cache"
run() {
	PATH="$SYS/bin:/usr/bin:/bin" STUB_VERSION="$1" SOFTHSM_CACHE="$CACHE" \
		SOFTHSM_BUILD_SCRIPT="$BUILD" bash "$SCRIPT" 2>"$WORK/stderr"
}
built() { [ -f "$WORK/built" ] && wc -l <"$WORK/built" | tr -d ' ' || echo 0; }

section "a system SoftHSM 2.7.0 or newer is used as it is"
for v in 2.7.0 2.7.1 2.10.0; do
	rm -f "$WORK/built"
	out=$(run "$v")
	rc=$?
	eq "$v: exit 0" 0 "$rc"
	eq "$v: prints the system module" "$SYS/lib/softhsm/libsofthsm2.so" "$out"
	eq "$v: nothing is built" 0 "$(built)"
done
if [ -e "$CACHE" ]; then no "no cache is created" "absent" "present"; else ok "no cache is created"; fi

section "a system SoftHSM older than 2.7.0 selects the cache build"
rm -f "$WORK/built"
out=$(run 2.6.1)
rc=$?
eq "exit 0" 0 "$rc"
eq "prints the cache module" "$CACHE/usr/lib/softhsm/libsofthsm2.so" "$out"
eq "the pinned release is built once" 1 "$(built)"
if [ -f "$CACHE/usr/lib/softhsm/libsofthsm2.so" ]; then ok "the cache holds the module"; else no "the cache holds the module" "a file" "missing"; fi
eq "no temporary build directory is left" "cache" "$(ls -A "$WORK" | grep '^cache' | tr '\n' ' ' | tr -d ' ')"

section "an existing cache build is reused without rebuilding"
rm -f "$WORK/built"
out=$(run 2.6.1)
rc=$?
eq "exit 0" 0 "$rc"
eq "prints the cache module" "$CACHE/usr/lib/softhsm/libsofthsm2.so" "$out"
eq "nothing is rebuilt" 0 "$(built)"

section "a failed build leaves no cache and fails"
rm -rf "$CACHE" "$WORK/built"
printf '#!/bin/sh\nSOFTHSM_VERSION=2.7.0\necho build >>"%s/built"\nexit 1\n' "$WORK" >"$BUILD"
out=$(run 2.6.1)
rc=$?
if [ "$rc" -ne 0 ]; then ok "non-zero exit"; else no "non-zero exit" "rc != 0" "$rc"; fi
eq "prints no path" "" "$out"
if [ -e "$CACHE" ]; then no "no cache is left" "absent" "present"; else ok "no cache is left"; fi

printf '\npassed %d, failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
