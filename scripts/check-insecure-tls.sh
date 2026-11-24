#!/usr/bin/env bash
#
# check-insecure-tls.sh: InsecureSkipVerify and insecure-transport gate.
set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
cd "$ROOT" || exit 1

GREP_EXCLUDES=(
	--exclude-dir=.git
	--exclude=.git
	--exclude-dir=vendor
)

violations=""

add_violations() {
	if [ -n "$1" ]; then
		violations="${violations}${violations:+$'\n'}$1"
	fi
}

# Drop full-line comments (leading whitespace then //): a mention of the
# pattern in prose, not a live struct field or call.
strip_comment_lines() {
	grep -Pv '^[^:]+:[0-9]+:[[:space:]]*//'
}

# ---------------------------------------------------------------------------
# Checks 1 + 2: InsecureSkipVerify set to anything but the literal `false`,
# as a struct-literal field (`:`) or an assignment (`=`, not `==`).
#
# Allowlist -- each bypasses cert verification deliberately, with its own
# compensating control (an SPKI pin is the sole verifier via
# VerifyConnection), and carries an in-file `#nosec G402` + "Allowlisted in
# Makefile check-insecure-tls" comment:
allow_skipverify=(
	'pkg/crypto/spki/spki.go'
	'pkg/trust/fetcher/spki.go'
	'pkg/trust/bootstrap/tofu_tls.go'
)

skipverify_matches=$(grep -rPn 'InsecureSkipVerify[[:space:]]*:[[:space:]]*(?!false\b)\S|\.InsecureSkipVerify[[:space:]]*=(?!=)[[:space:]]*(?!false\b)\S' \
	--include="*.go" "${GREP_EXCLUDES[@]}" . | strip_comment_lines || true)
for f in "${allow_skipverify[@]}"; do
	skipverify_matches=$(printf '%s\n' "$skipverify_matches" | grep -v "$f" || true)
done
add_violations "$skipverify_matches"

# ---------------------------------------------------------------------------
# Check 3: Insecure: true in the Vault backend's TLS config. No allowlist --
# vault.TLSConfig has a CACert/CAPath + ClientCert/ClientKey path for every
# case this backend needs (go-xkms#1284); there is no reviewed exception.
vault_insecure_matches=$(grep -rPn 'Insecure[[:space:]]*:[[:space:]]*true' \
	--include="*.go" "${GREP_EXCLUDES[@]}" pkg/backend/vault 2>/dev/null | strip_comment_lines || true)
add_violations "$vault_insecure_matches"

# ---------------------------------------------------------------------------
# Check 4: insecure.NewCredentials() in production code without a trailing
# `insecure-ok:` justification comment on the same line. _test.go files are
# excluded (see file header).
newcreds_matches=$(grep -rPn 'insecure\.NewCredentials\(\)' \
	--include="*.go" --exclude="*_test.go" "${GREP_EXCLUDES[@]}" . | strip_comment_lines || true)
newcreds_matches=$(printf '%s\n' "$newcreds_matches" | grep -v 'insecure-ok:' || true)
add_violations "$newcreds_matches"

if [ -n "$violations" ]; then
	echo "check-insecure-tls.sh: FORBIDDEN insecure TLS/transport usage outside allowlist (go-xkms#1284):" >&2
	# path:line only, never the matched source line (handbook ci-standard.md §5).
	printf '%s\n' "$violations" | cut -d: -f1,2 | sed "s#^#  #" >&2
	exit 1
fi

echo "check-insecure-tls.sh: clean -- InsecureSkipVerify, vault TLS, and insecure.NewCredentials() allowlists hold" >&2
exit 0
