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
#   STRICT=1     treat the first step that does not work as a failure:
#                print FAIL and exit 1 there
#
# Each step prints "OK step N", "STOP step N: <call> -> <answer>" (the step
# does not work yet: the run ends its path there), "NOT REACHED step N" or
# "BOUNDARY ca: ..." (the expected rejection of a call made without
# credentials). The ACME path stops at its first step that does not work and
# the certificate-authority path (SignCSR) runs next. The script ends at the
# last working step with exit 0; it exits 1 when the board is unreachable,
# when a call that must be refused succeeds ("FAIL step N"), or, with
# STRICT=1, at the first STOP. It never runs init, never changes the board's
# configuration and never prints a token, key or secret.
set -euo pipefail

: "${BOARD:?export BOARD=host:port of the board}"
ACME_DIR="${ACME_DIR:-https://${BOARD}/acme/directory}"
WORK="${WORK:-$(mktemp -d)}"
CA_PEM="$WORK/board-ca.pem"
FAILS=0
LAST_OK=none

ok() {
	echo "OK step $1"
	LAST_OK=$1
}

# stop marks the step where a path ends because it does not work yet.
stop() {
	if [[ "${STRICT:-0}" == "1" ]]; then
		echo "FAIL step $1: $2"
		exit 1
	fi
	echo "STOP step $1: $2"
}

# fail marks a defect: an answer the board must never give.
fail() {
	echo "FAIL step $1: $2"
	FAILS=$((FAILS + 1))
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
		echo "the board serves its leaf only: no CA in the chain: curl keeps -k, step 2 fails"
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
		stop 1 "GET directory -> HTTP ${code} $(body "$WORK/directory.json")"
		return 1
	fi
	ok 1
}

# Step 2: account. The nonce first (RFC 8555 7.2), then the headless
# client's account, configured locally: account add sends no newAccount
# (docs/acme-issuance/cli.md), the first order registers it. The client
# trusts no system roots, so the account carries the board CA from step 0.
step2_account() {
	echo "== step 2: account"
	local code nonce_url line
	nonce_url="${ACME_DIR%/directory}/new-nonce"
	if command -v jq >/dev/null 2>&1 && [[ -s "$WORK/directory.json" ]]; then
		nonce_url=$(jq -r '.newNonce // empty' "$WORK/directory.json" 2>/dev/null || echo "$nonce_url")
	fi
	code=$(curl_board -o /dev/null -w '%{http_code}' -I "$nonce_url" || true)
	echo "HEAD new-nonce: HTTP ${code}"
	if [[ "$code" != "200" && "$code" != "204" ]]; then
		stop 2 "HEAD new-nonce -> HTTP ${code}"
		return 1
	fi
	if [[ ! -s "$CA_PEM" ]]; then
		stop 2 "no board CA from step 0: the client trusts no system roots, so it cannot reach ${ACME_DIR}"
		return 1
	fi
	if [[ -z "${ACME_CLIENT:-}" ]]; then
		stop 2 "ACME_CLIENT unset: the account is not configured"
		return 1
	fi
	mkdir -p "$WORK/client"
	{
		printf 'storage:\n  backend: filesystem\n  options:\n    path: %s/storage\n' "$WORK/client"
		printf 'xkms:\n  backend: software\n  options:\n    path: %s/keys\n' "$WORK/client"
		printf 'accounts:\n  e2e:\n    directory: %s\n    email: e2e@example.invalid\n' "$ACME_DIR"
		printf '    key:\n      algorithm: ECDSA\n      store: software\n      ecc:\n        curve: P-256\n'
		printf '    trusted_roots:\n      - |\n'
		while IFS= read -r line; do printf '        %s\n' "$line"; done <"$CA_PEM"
	} >"$WORK/client/config.yaml"
	if ! HOME="$WORK/client" "$ACME_CLIENT" -c "$WORK/client/config.yaml" --log-format text \
		account show e2e >"$WORK/client/show.log" 2>&1; then
		stop 2 "acme-client account show -> $(tail -n 1 "$WORK/client/show.log")"
		return 1
	fi
	echo "account e2e configured with the board CA; newAccount is sent with the first order"
	ok 2
}

# not_reached_from N reports the ACME steps from N to 6 as not reached; steps
# 3 to 6 (new account with the first order, challenge, finalize,
# certificate) are not scripted yet.
not_reached_from() {
	local s
	for s in "2 account" "3 new-account + new-order" "4 challenge" "5 finalize" "6 certificate chain + tenant OU"; do
		if ((${s%% *} >= $1)); then echo "NOT REACHED step ${s}"; fi
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
	case "$code" in
	401 | 403)
		echo "BOUNDARY ca: SignCSR without credentials is refused (HTTP ${code}), as it must be; enrolment through the CA path needs a client certificate or token (#2253, #2254)"
		;;
	200 | 201)
		fail ca "POST /api/v1/ca/sign-csr without credentials -> HTTP ${code}: the board signed a CSR for an unauthenticated caller"
		;;
	*)
		stop ca "POST /api/v1/ca/sign-csr without credentials -> HTTP ${code} $(body "$WORK/signcsr.out")"
		;;
	esac
}

step0_board
if step1_directory; then
	step2_account || true
	not_reached_from 3
else
	not_reached_from 2
fi
step_ca_signcsr
echo "== done: last working step: ${LAST_OK}; ${FAILS} failed step(s); work dir ${WORK}"
if ((FAILS > 0)); then exit 1; fi
exit 0
