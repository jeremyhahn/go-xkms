#!/usr/bin/env bash
# Enrolment end to end against the xkmsd that runs on the i.MX 95 board
# (row enrolment-imx95-e2e, issue #2258).
#
# Environment:
#   BOARD        host:port of the board's xkmsd API listener (required)
#   ACME_DIR     ACME directory URL (default https://$BOARD/acme/directory)
#   ACME_CLIENT  path of a headless acme-client built with
#                -tags "codec_cbor codec_json codec_msgpack" (optional)
#   WORK         scratch directory (default: a new mktemp -d)
#   STRICT=1     exit 1 at the first gap instead of 0
#
# Each step prints "OK step N" or "GAP step N: <call> -> <answer>". The ACME
# path stops at its first gap and the certificate-authority path (SignCSR)
# runs next. The script exits 0 when every step that works passed and the
# run ended at a recorded gap; it exits 1 when the board is unreachable.
# It never runs init, never changes the board's configuration and never
# prints a token, key or secret.
set -euo pipefail

: "${BOARD:?export BOARD=host:port of the board}"
ACME_DIR="${ACME_DIR:-https://${BOARD}/acme/directory}"
WORK="${WORK:-$(mktemp -d)}"
CA_PEM="$WORK/board-ca.pem"
GAPS=0

ok() { echo "OK step $1"; }
gap() {
	echo "GAP step $1: $2"
	GAPS=$((GAPS + 1))
	if [[ "${STRICT:-0}" == "1" ]]; then exit 1; fi
}

# curl_board trusts the board CA once step 1 has saved it.
curl_board() {
	if [[ -s "$CA_PEM" ]]; then
		curl -s --max-time 15 --cacert "$CA_PEM" "$@"
	else
		curl -sk --max-time 15 "$@"
	fi
}

body() { head -c 160 "$1" | tr -d '\n'; }

json_keys() {
	if command -v jq >/dev/null 2>&1; then
		jq -r 'keys | join(" ")' "$1" 2>/dev/null || body "$1"
	else
		body "$1"
	fi
	echo
}

# Step 0: the board answers TLS and /health; save the issuing CA it serves
# (the last certificate of the chain) so later calls verify against it.
step0_board() {
	echo "== step 0: board reachable"
	local code
	openssl s_client -connect "$BOARD" -showcerts </dev/null >"$WORK/chain.txt" 2>/dev/null || true
	if ! openssl x509 -in "$WORK/chain.txt" -noout -subject -issuer 2>/dev/null; then
		echo "board unreachable over TLS"
		exit 1
	fi
	# Split the served chain; keep the last certificate as the board CA when
	# the server sends it (a leaf-only chain leaves CA_PEM empty: -k is kept).
	awk_free_split "$WORK/chain.txt"
	code=$(curl_board -o "$WORK/health.json" -w '%{http_code}' "https://${BOARD}/health" || true)
	echo "GET /health: HTTP ${code}"
	[[ "$code" == "200" ]] || {
		echo "board /health not 200"
		exit 1
	}
	ok 0
}

# awk_free_split writes every PEM certificate of $1 after the first to
# CA_PEM (bash only).
awk_free_split() {
	local line n=0 in=0
	: >"$CA_PEM"
	while IFS= read -r line; do
		if [[ "$line" == "-----BEGIN CERTIFICATE-----" ]]; then
			n=$((n + 1))
			in=1
		fi
		if ((in == 1 && n > 1)); then echo "$line" >>"$CA_PEM"; fi
		if [[ "$line" == "-----END CERTIFICATE-----" ]]; then in=0; fi
	done <"$1"
	if [[ -s "$CA_PEM" ]]; then
		echo "board CA saved from the served chain"
	else
		echo "the board serves its leaf only: no CA in the chain, calls keep -k"
	fi
}

# Step 1: the ACME directory (RFC 8555 7.1.1).
step1_directory() {
	echo "== step 1: ACME directory"
	local code
	code=$(curl_board -o "$WORK/directory.json" -w '%{http_code}' "$ACME_DIR" || true)
	echo "GET ${ACME_DIR#https://"$BOARD"}: HTTP ${code}"
	json_keys "$WORK/directory.json"
	if [[ "$code" != "200" ]]; then
		gap 1 "GET directory -> HTTP ${code} $(body "$WORK/directory.json")"
		return 1
	fi
	ok 1
}

# Step 2: new account. The nonce first (RFC 8555 7.2), then the headless
# client's account add, which registers when a client is built.
step2_account() {
	echo "== step 2: new account"
	local code nonce_url
	nonce_url="${ACME_DIR%/directory}/new-nonce"
	if command -v jq >/dev/null 2>&1 && [[ -s "$WORK/directory.json" ]]; then
		nonce_url=$(jq -r '.newNonce // empty' "$WORK/directory.json" 2>/dev/null || echo "$nonce_url")
	fi
	code=$(curl_board -o /dev/null -w '%{http_code}' -I "$nonce_url" || true)
	echo "HEAD new-nonce: HTTP ${code}"
	if [[ "$code" != "200" && "$code" != "204" ]]; then
		gap 2 "HEAD new-nonce -> HTTP ${code}"
		return 1
	fi
	if [[ -z "${ACME_CLIENT:-}" ]]; then
		gap 2 "ACME_CLIENT unset: new-account not attempted"
		return 1
	fi
	mkdir -p "$WORK/client"
	printf 'storage:\n  backend: filesystem\n  options:\n    path: %s/storage\nxkms:\n  backend: software\n  options:\n    path: %s/keys\n' \
		"$WORK/client" "$WORK/client" >"$WORK/client/config.yaml"
	if ! HOME="$WORK/client" "$ACME_CLIENT" -c "$WORK/client/config.yaml" --log-format text \
		account add e2e --directory "$ACME_DIR" --email e2e@example.invalid >"$WORK/client/add.log" 2>&1; then
		gap 2 "acme-client account add -> $(tail -n 1 "$WORK/client/add.log")"
		return 1
	fi
	if ! HOME="$WORK/client" "$ACME_CLIENT" -c "$WORK/client/config.yaml" --log-format text \
		account show e2e >"$WORK/client/show.log" 2>&1; then
		gap 2 "acme-client account show after add -> $(tail -n 1 "$WORK/client/show.log")"
		return 1
	fi
	ok 2
}

# Steps 3 to 6 (order, challenge, finalize, certificate) need a registered
# account; they are reported as not reached until steps 1 and 2 work.
steps3to6_not_reached() {
	local s
	for s in "2 new-account (if step 1 failed)" "3 new-order" "4 challenge" "5 finalize" "6 certificate chain + tenant OU"; do
		echo "NOT REACHED step ${s}"
	done
}

# Certificate-authority path: SignCSR over the REST API with the
# credentials this node has (none: no admin client certificate, no token).
step_ca_signcsr() {
	echo "== CA path: POST /api/v1/ca/sign-csr"
	local code
	openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-keyout "$WORK/csr.key" -subj "/O=go-xkms/OU=system/CN=e2e-enrolment" \
		-out "$WORK/e2e.csr" 2>/dev/null
	jq -n --rawfile csr "$WORK/e2e.csr" '{csr: $csr}' >"$WORK/signcsr.json" 2>/dev/null ||
		printf '{"csr":"%s"}' "$(tr '\n' '|' <"$WORK/e2e.csr" | tr -d '|')" >"$WORK/signcsr.json"
	code=$(curl_board -o "$WORK/signcsr.out" -w '%{http_code}' -H 'Content-Type: application/json' \
		--data @"$WORK/signcsr.json" "https://${BOARD}/api/v1/ca/sign-csr" || true)
	echo "POST /api/v1/ca/sign-csr: HTTP ${code}"
	if [[ "$code" != "200" && "$code" != "201" ]]; then
		gap ca "POST /api/v1/ca/sign-csr without credentials -> HTTP ${code} $(body "$WORK/signcsr.out")"
		return 1
	fi
	ok ca
}

step0_board
if step1_directory && step2_account; then
	echo "steps 3 to 6 are not scripted yet: extend here once step 2 works"
else
	steps3to6_not_reached
fi
step_ca_signcsr || true
echo "== done: ${GAPS} gap(s); work dir ${WORK}"
exit 0
