#!/usr/bin/env bash
#
# check-insecure-tls.sh — InsecureSkipVerify / insecure-transport gate
# (go-xkms#1284).
#
# Fails with file:line output if production Go code bypasses TLS server
# certificate verification, or dials gRPC with no transport security at
# all, outside a short, reviewed allowlist. Four independent checks:
#
#   1. `InsecureSkipVerify: <value>` (struct-literal field) where <value>
#      is anything but the literal `false`. This covers both
#      `InsecureSkipVerify: true` and a non-literal value such as a
#      variable or another struct's field -- either defeats a reviewer
#      grepping for the literal `true` to confirm the flag is off.
#   2. The assignment form `.InsecureSkipVerify = <value>`, same
#      non-`false` rule. `==` (a comparison, e.g. in a test assertion) is
#      deliberately not matched.
#   3. `Insecure: true` inside pkg/backend/vault -- HashiCorp Vault's
#      TLSConfig.Insecure has the same effect as InsecureSkipVerify but a
#      different field name, so checks 1-2 do not see it. Scoped to the
#      vault backend because `Insecure`/`AllowInsecure` fields elsewhere in
#      the tree (transport.Config, gcpkms.Config, KeyProtection) mean a
#      config choice to skip TLS/authentication entirely, not a bypass of
#      certificate verification on a connection that claims to be secure --
#      a materially different risk this check does not attempt to police.
#   4. `insecure.NewCredentials()` (the grpc-go credentials that skip
#      transport security entirely) in production code, unless the call
#      carries a trailing `// insecure-ok: ...` justification comment.
#      _test.go files are excluded: bufconn and other in-memory test
#      transports have no network path for a MITM, and are pervasive
#      enough (see `git grep -l insecure.NewCredentials -- '*_test.go'`)
#      that policing them here would not be reviewing anything real.
#
# The allowlists below are these checks' entire enforcement surface --
# adding a file/line to one is a security-relevant change and should read
# like one.
#
# Usage: scripts/check-insecure-tls.sh [ROOT]
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
	printf '%s\n' "$violations" | sed "s#^#  #" >&2
	exit 1
fi

echo "check-insecure-tls.sh: clean -- InsecureSkipVerify, vault TLS, and insecure.NewCredentials() allowlists hold" >&2
exit 0
