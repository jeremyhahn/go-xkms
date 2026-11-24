#!/bin/sh
#
# vet-integration.sh: compile-only gate for every suite under test/integration.
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

TAG_LINES=$(mktemp)
TAG_SETS=$(mktemp)
trap 'rm -f "$TAG_LINES" "$TAG_SETS"' EXIT INT TERM

find test/integration -name '*.go' -print0 \
	| xargs -0 grep -h '^//go:build ' \
	| sed 's#^//go:build ##' \
	>"$TAG_LINES"

if [ ! -s "$TAG_LINES" ]; then
	echo "vet-integration: no //go:build lines found under test/integration" >&2
	exit 1
fi

while IFS= read -r expr; do
	printf '%s\n' "$expr" \
		| tr '()' '  ' \
		| tr -s '\t ' '\n' \
		| awk '
			/^&&$/ || /^\|\|$/ || $0 == "" { next }
			/^!/ { next }
			{ print }
		' \
		| sort -u \
		| tr '\n' ' ' \
		| sed 's/[[:space:]]*$//' \
		>>"$TAG_SETS"
	printf '\n' >>"$TAG_SETS"
done <"$TAG_LINES"

UNIQUE_SETS=$(mktemp)
trap 'rm -f "$TAG_LINES" "$TAG_SETS" "$UNIQUE_SETS"' EXIT INT TERM
sort -u "$TAG_SETS" | grep -v '^$' >"$UNIQUE_SETS" || true

count=$(wc -l <"$UNIQUE_SETS" | tr -d ' ')
echo "vet-integration: ${count} distinct build-tag combination(s) under test/integration"

status=0
while IFS= read -r tagset; do
	echo "  -> go vet -tags \"${tagset}\" ./test/integration/..."
	if ! go vet -tags "${tagset}" ./test/integration/...; then
		echo "vet-integration: FAILED for tags: ${tagset}" >&2
		status=1
	fi
done <"$UNIQUE_SETS"

exit "$status"
