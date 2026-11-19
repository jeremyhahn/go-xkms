#!/usr/bin/env bash
# go-caches-env.test.sh: an `env -i` sub-make keeps the caller's Go caches
# (#2295). With HOME=H and GOMODCACHE=D (both empty temp dirs), neither a bare
# Makefile parse nor test/scripts/gomodauth.test.sh may create H/go/pkg/mod.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
cleanup() {
	chmod -R u+w "$WORK" 2>/dev/null || true
	rm -rf "$WORK"
}
trap cleanup EXIT

PASS=0
FAIL=0

# no_home_modcache NAME H: H/go/pkg/mod must not exist.
no_home_modcache() {
	if [ -e "$2/go/pkg/mod" ]; then
		printf 'FAIL %s: %s/go/pkg/mod was written\n' "$1" "$2"
		FAIL=$((FAIL + 1))
	else
		printf 'ok   %s\n' "$1"
		PASS=$((PASS + 1))
	fi
}

# Makefile parse under the env -i form the test scripts use.
H="$WORK/parse-home"
D="$WORK/parse-modcache"
mkdir -p "$H" "$D"
env -i PATH="$PATH" HOME="$H" GOMODCACHE="$D" GOFLAGS=-mod=mod \
	make -s --no-print-directory -C "$ROOT" -n help >"$WORK/parse.out" 2>&1 || {
	echo "make -n help failed:" >&2
	tail -n 20 "$WORK/parse.out" >&2
	exit 1
}
no_home_modcache "make parse under env -i" "$H"
# A parse runs no Go command that fills a module cache (PKG_DIRS deferred).
if [ -n "$(ls -A "$D")" ]; then
	printf 'FAIL make parse: it wrote the module cache %s\n' "$D"
	FAIL=$((FAIL + 1))
else
	printf 'ok   make parse leaves GOMODCACHE empty\n'
	PASS=$((PASS + 1))
fi

# gomodauth.test.sh runs make under env -i (via_make): it must carry
# GOMODCACHE through.
H="$WORK/gomodauth-home"
D="$WORK/gomodauth-modcache"
mkdir -p "$H" "$D"
if ! HOME="$H" GOMODCACHE="$D" bash "$ROOT/test/scripts/gomodauth.test.sh" >"$WORK/gomodauth.out" 2>&1; then
	echo "gomodauth.test.sh failed:" >&2
	tail -n 20 "$WORK/gomodauth.out" >&2
	FAIL=$((FAIL + 1))
fi
no_home_modcache "gomodauth.test.sh via_make" "$H"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
