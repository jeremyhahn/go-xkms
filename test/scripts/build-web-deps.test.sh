#!/usr/bin/env bash
# build-web-deps.test.sh: `make build-web` must install the
# sdk/ts/svelte-auth dependencies before it builds web/app (#2286 item 2).
# svelte-auth resolves its @go-xkms/sdk devDependency (file:..) only through
# its own node_modules, so a clean checkout fails the web/app Rollup build
# without that npm ci. The check is a make dry run: no npm is executed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

plan="$(make -s -C "$ROOT" -n build-web NPM=npm 2>/dev/null)"

auth_line=0
build_line=0
n=0
while IFS= read -r line; do
	n=$((n + 1))
	if [[ $auth_line -eq 0 && $line == *"cd sdk/ts/svelte-auth"*"npm ci"* ]]; then
		auth_line=$n
	fi
	if [[ $build_line -eq 0 && $line == *"cd web/app"*"npm run build"* ]]; then
		build_line=$n
	fi
done <<<"$plan"

fail() {
	echo "FAIL: build-web-deps: $1" >&2
	exit 1
}

[[ $build_line -gt 0 ]] || fail "make -n build-web shows no web/app npm run build"
[[ $auth_line -gt 0 ]] || fail "make -n build-web runs no npm ci in sdk/ts/svelte-auth"
[[ $auth_line -lt $build_line ]] || fail "svelte-auth npm ci runs after the web/app build"

echo "PASS: build-web-deps"
