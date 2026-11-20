#!/usr/bin/env bash
# go-caches-env.test.sh: an `env -i` sub-make keeps the caller's Go caches
# (#2295). With HOME=H and GOMODCACHE=D (both empty temp dirs), neither a bare
# Makefile parse nor test/scripts/gomodauth.test.sh may create H/go/pkg/mod, and
# the env -i sub-make must see the caller's GOMODCACHE/GOCACHE as set, unset or
# empty exactly as the caller had them.
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

# Inside the env -i child: a make shim first on PATH (env -i keeps PATH)
# records what the sub-make sees of GOMODCACHE and GOCACHE, then runs the
# real make. A set, an unset and an explicitly empty caller value must each
# reach the child unchanged, so dropping GO_CACHE_ENV fails here.
REAL_MAKE="$(command -v make)"
SHIM="$WORK/shim"
REC="$WORK/make-env.rec"
mkdir -p "$SHIM"
cat >"$SHIM/make" <<SHIM_EOF
#!/usr/bin/env bash
for v in GOMODCACHE GOCACHE; do
	if [ -n "\${!v+x}" ]; then printf '%s=set:%s\n' "\$v" "\${!v}"; else printf '%s=unset\n' "\$v"; fi
done >>"$REC"
exec "$REAL_MAKE" "\$@"
SHIM_EOF
chmod +x "$SHIM/make"

# child_sees LABEL WANT_GOMODCACHE WANT_GOCACHE -- ENV...: runs gomodauth.test.sh
# with ENV (env(1) arguments) and the shim on PATH; every sub-make must record
# the two wanted lines.
child_sees() {
	local label=$1 want_mod=$2 want_cache=$3 h="$WORK/$1-home" line bad=0 n=0
	shift 4
	mkdir -p "$h"
	: >"$REC"
	if ! env "$@" HOME="$h" PATH="$SHIM:$PATH" \
		bash "$ROOT/test/scripts/gomodauth.test.sh" >"$WORK/$label.out" 2>&1; then
		echo "gomodauth.test.sh ($label) failed:" >&2
		tail -n 20 "$WORK/$label.out" >&2
		bad=1
	fi
	while IFS= read -r line; do
		n=$((n + 1))
		case $line in
		GOMODCACHE=*) [ "$line" = "GOMODCACHE=$want_mod" ] || bad=1 ;;
		GOCACHE=*) [ "$line" = "GOCACHE=$want_cache" ] || bad=1 ;;
		esac
	done <"$REC"
	if [ "$n" -eq 0 ] || [ "$bad" -ne 0 ]; then
		printf 'FAIL env -i child, %s: want GOMODCACHE=%s GOCACHE=%s, got: %s\n' \
			"$label" "$want_mod" "$want_cache" "$(tr '\n' ' ' <"$REC")"
		FAIL=$((FAIL + 1))
	else
		printf 'ok   env -i child, %s\n' "$label"
		PASS=$((PASS + 1))
	fi
}

child_sees set "set:$WORK/set-mod" "set:$WORK/set-cache" -- \
	GOMODCACHE="$WORK/set-mod" GOCACHE="$WORK/set-cache"
child_sees unset unset unset -- -u GOMODCACHE -u GOCACHE
child_sees empty "set:" "set:" -- GOMODCACHE= GOCACHE=

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
