#!/usr/bin/env bash
# Tests that no make target or gate prints a credential or a matched source
# line (handbook ci-template v1.21.1, ci-standard.md §5): `make
# stage-gomodauth` stays silent about the values it writes, and the lint and
# check gates report path and line only.
#
# Every planted value is obviously fake.
#
# Usage: bash test/scripts/no-credential-echo.test.sh

set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

FAKE_TOKEN=FAKE-TOKEN-0000-not-a-credential
FAKE_KEY="url.https://fake-user:${FAKE_TOKEN}@forge.example.invalid/jeremyhahn/.insteadOf"
FAKE_VALUE="https://fake-user:${FAKE_TOKEN}@forge.example.invalid/jeremyhahn/"

failures=0

fail() {
	echo "FAIL: $*" >&2
	failures=$((failures + 1))
}

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

# --- make stage-gomodauth writes the planted values and prints none of them.
out=$(cd "$ROOT" && GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="$FAKE_KEY" GIT_CONFIG_VALUE_0="$FAKE_VALUE" \
	make --no-print-directory stage-gomodauth GOMODAUTH_FILE="$scratch/gomodauth.env" 2>&1)
rc=$?
[ "$rc" -eq 0 ] || fail "make stage-gomodauth exited $rc"
case $out in
*"$FAKE_TOKEN"*) fail "make stage-gomodauth printed the planted credential" ;;
esac
staged=$(<"$scratch/gomodauth.env")
case $staged in
*"$FAKE_TOKEN"*) ;;
*) fail "make stage-gomodauth did not stage the planted credential, so the silence check proves nothing" ;;
esac

# --- check-insecure-tls reports a planted finding by path and line only.
mkdir -p "$scratch/tree/pkg/leak"
printf 'package leak\n\nvar cfg = tls.Config{InsecureSkipVerify: true} // %s\n' "$FAKE_TOKEN" \
	>"$scratch/tree/pkg/leak/leak.go"
out=$(bash "$ROOT/scripts/check-insecure-tls.sh" "$scratch/tree" 2>&1)
rc=$?
[ "$rc" -ne 0 ] || fail "check-insecure-tls passed a planted InsecureSkipVerify finding"
case $out in
*"pkg/leak/leak.go:3"*) ;;
*) fail "check-insecure-tls did not name the finding's path:line" ;;
esac
case $out in
*"$FAKE_TOKEN"* | *"InsecureSkipVerify: true"*) fail "check-insecure-tls printed the matched source line" ;;
esac

# --- golangci-lint and actionlint are configured without source excerpts.
golangci_issued=0
while IFS= read -r line; do
	[ "${line// /}" = "print-issued-lines:false" ] && golangci_issued=1
done <"$ROOT/.golangci.yml"
[ "$golangci_issued" -eq 1 ] || fail ".golangci.yml does not set print-issued-lines: false"

actionlint_format=$(cd "$ROOT" && make --no-print-directory -s -f Makefile -f - print-actionlint-format <<'EOF'
print-actionlint-format:
	@printf '%s\n' '$(ACTIONLINT_FORMAT)'
EOF
)
case $actionlint_format in
*'{{range'*'.Filepath'*'.Line'*'.Message'*) ;;
*) fail "ACTIONLINT_FORMAT is not a path:line:message template" ;;
esac
case $actionlint_format in
*Snippet*) fail "ACTIONLINT_FORMAT prints the source snippet" ;;
esac

if [ "$failures" -ne 0 ]; then
	echo "no-credential-echo: $failures failure(s)" >&2
	exit 1
fi
echo "no-credential-echo: ok"
