#!/usr/bin/env bash
# Tests that every path a module-fetch credential is written to stays out of
# git and out of every Docker build context that can reach it (#1600). The
# pre-#1558 .devcontainer/ paths stay listed: an upgraded checkout keeps its
# old untracked .devcontainer/.env, and `COPY . .` would bake it into a layer.
#
# Usage: bash test/scripts/credential-ignores.test.sh

set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
DEVCONTAINER=build/docker/devcontainer

# Credential files relative to the repository root: what `make
# devcontainer-env` and `make stage-gomodauth` write (.env.tmp is the
# rewrite's transient copy), at the current and the pre-#1558 location.
CREDENTIAL_PATHS=(
	"$DEVCONTAINER/.env"
	"$DEVCONTAINER/.env.tmp"
	"$DEVCONTAINER/gomodauth.env"
	.devcontainer/.env
	.devcontainer/.env.tmp
	.devcontainer/gomodauth.env
	gomodauth.env
)

# Credential files relative to $DEVCONTAINER, the build context compose.yaml
# gives softfido and virt-piv.
DEVCONTAINER_CONTEXT_PATHS=(.env .env.tmp gomodauth.env)

failures=0

fail() {
	echo "FAIL: $*" >&2
	failures=$((failures + 1))
}

# has_line FILE LINE succeeds when FILE carries LINE as a whole pattern line.
has_line() {
	local file=$1 line=$2 entry
	while IFS= read -r entry; do
		[ "$entry" = "$line" ] && return 0
	done <"$file"
	return 1
}

# dockerignore_covers FILE PATH succeeds when FILE excludes PATH by an exact
# line, or PATH is gomodauth.env-shaped and FILE carries the gomodauth* glob
# at the same directory level.
dockerignore_covers() {
	local file=$1 path=$2 dir base
	has_line "$file" "$path" && return 0
	base=${path##*/}
	dir=${path%"$base"}
	case "$base" in
	gomodauth*) has_line "$file" "${dir}gomodauth*" && return 0 ;;
	esac
	return 1
}

for path in "${CREDENTIAL_PATHS[@]}"; do
	git -C "$ROOT" check-ignore -q --no-index "$path" ||
		fail ".gitignore does not ignore $path"
	dockerignore_covers "$ROOT/.dockerignore" "$path" ||
		fail ".dockerignore does not exclude $path"
done

if [ -f "$ROOT/$DEVCONTAINER/.dockerignore" ]; then
	for path in "${DEVCONTAINER_CONTEXT_PATHS[@]}"; do
		dockerignore_covers "$ROOT/$DEVCONTAINER/.dockerignore" "$path" ||
			fail "$DEVCONTAINER/.dockerignore does not exclude $path"
	done
else
	fail "$DEVCONTAINER/.dockerignore is missing"
fi

# The test must catch a dropped entry, not only pass on the real files.
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
printf 'gomodauth*\n%s/.env\n' "$DEVCONTAINER" >"$scratch/.dockerignore"
dockerignore_covers "$scratch/.dockerignore" .devcontainer/.env &&
	fail "dockerignore_covers accepted a file without .devcontainer/.env"
dockerignore_covers "$scratch/.dockerignore" "$DEVCONTAINER/gomodauth.env" &&
	fail "dockerignore_covers let the root gomodauth* glob cover a subdirectory"

if [ "$failures" -ne 0 ]; then
	echo "credential-ignores: $failures failure(s)" >&2
	exit 1
fi
echo "credential-ignores: ok"
