#!/usr/bin/env bash
# Enrolment end to end against the xkmsd that runs on the i.MX 95 board
# (row enrolment-imx95-e2e, issue #2258).
#
# Environment:
#   BOARD      host:port of the board's xkmsd API listener (required)
#   ACME_DIR   ACME directory URL (default https://$BOARD/acme/directory)
#   BOARD_CA   PEM file of the board CA; when unset, step 1 saves the chain
#              the API listener serves to $WORK/board-chain.pem and later
#              calls run with -k
#   WORK       scratch directory (default: a new mktemp -d)
#
# The script never writes to the board beyond the ACME protocol calls, and
# never prints a token, key or secret.
set -euo pipefail

: "${BOARD:?export BOARD=host:port of the board}"
ACME_DIR="${ACME_DIR:-https://${BOARD}/acme/directory}"
WORK="${WORK:-$(mktemp -d)}"

curl_board() {
	if [[ -n "${BOARD_CA:-}" ]]; then
		curl -s --max-time 15 --cacert "$BOARD_CA" "$@"
	else
		curl -sk --max-time 15 "$@"
	fi
}

json_keys() {
	if command -v jq >/dev/null 2>&1; then
		jq -r 'keys[]' "$1" 2>/dev/null || head -c 200 "$1"
	else
		head -c 400 "$1"
	fi
	echo
}

step1_directory() {
	echo "== step 1: ACME directory"
	local health_code code
	health_code=$(curl_board -o "$WORK/health.json" -w '%{http_code}' "https://${BOARD}/health" || true)
	echo "API /health: HTTP ${health_code}"
	openssl s_client -connect "$BOARD" -showcerts </dev/null >"$WORK/board-chain.pem" 2>/dev/null || true
	openssl x509 -in "$WORK/board-chain.pem" -noout -subject -issuer 2>/dev/null || true
	code=$(curl_board -o "$WORK/directory.json" -w '%{http_code}' "$ACME_DIR" || true)
	echo "ACME directory: HTTP ${code}"
	json_keys "$WORK/directory.json"
	[[ "$code" == "200" ]]
}

step1_directory
