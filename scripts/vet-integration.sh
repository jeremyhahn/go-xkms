#!/bin/sh
#
# vet-integration.sh -- compile-only gate for every suite under
# test/integration. Called by `make vet-integration`.
#
# WHY THIS EXISTS (go-xkms#650)
#
# `go vet ./...` from the root module never reaches a file gated behind
# `integration` (or any other suite tag) because that tag is never set: CI
# has never once type-checked these suites, which is how #636/#638 broke
# sdk/go and acme-tpm, and how the tpm2/idevid and tpm2/tpm_operations
# suites (this issue) drifted roughly 200 references behind
# pkg/tpm2/store's current API, unnoticed until an agent tripped over it.
#
# ONE TAG UNION IS THE WRONG FIX. Several suites are deliberately mutually
# exclusive within the same package -- acme-multiprotocol carries
# helpers_grpc.go (`integration && grpc`) beside helpers_nogrpc.go
# (`integration && !grpc`), and storage carries the pkcs11/!pkcs11 pair the
# same way -- so turning every tag on at once compiles both halves of each
# pair together and fails on a duplicate declaration that no real build
# configuration ever produces. This script instead discovers each file's OWN
# `//go:build` line and runs `go vet` once per DISTINCT tag combination, so
# every file is type-checked under a combination that actually satisfies its
# constraint, and no two mutually exclusive files ever share a run.
#
# DISCOVERY, NOT A HAND-MAINTAINED LIST. A list here is a list that drifts
# the moment someone adds a suite under a new tag and forgets to update it --
# exactly the blind spot this gate exists to close. Instead:
#
#   1. Collect every `//go:build` line under test/integration.
#   2. Reduce each line to the set of tags that must be ON to satisfy it:
#      split on `&&`/`||`, drop parentheses, and drop any `!negated` term
#      (leaving it off, its default, satisfies the negation). Setting every
#      remaining positive term ON satisfies any negation-free combination of
#      AND and OR over those terms -- which is all a Go build constraint can
#      express once negated terms are set aside.
#   3. De-duplicate the resulting tag sets and run one `go vet -tags "..."
#      ./test/integration/...` per set.
#
# This is compile-only. It never runs a test body, dials hardware, or
# touches the host -- exactly like `go vet` anywhere else in this Makefile.
# The suites themselves still run only in the devcontainer, via
# `make integration-test-*`.
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
