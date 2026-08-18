#!/bin/bash
# wait-quicbaas-login-planes.sh — block until the compose quicbaasd
# fixture's LOGIN PLANES actually serve, not merely until its TCP port
# answers. Two composition windows exist after boot: the xkms module's
# host REST engine builds lazily on first use and its identity clients
# (XKMSService.SetUserClients) are wired in startService, and quicbaas's
# own module REST surface late-binds behind the facade. A matrix run that
# starts inside either window fails with "subsystem not configured" /
# 404s that look like product bugs and are not.
#
# Readiness =
#   POST /api/v1/webauthn/registration/begin answers 200/400/422
#     (the xkms module's WebAuthn subsystem is composed; an empty body
#     is a 4xx from the live handler, never 500/503), AND
#   POST /api/v1/iam/login/piv answers 401 anonymously
#     (quicbaas's IAM surface is mounted; the handler demands a cert).
#
# This runs INSIDE the devcontainer (service DNS), invoked by the
# integration-test-logins-quicbaas Makefile lane. A script rather than an
# inline recipe: the readiness loop needs command substitution and case
# patterns, both of which are mangled by make's $(call) parentheses
# parsing and the run_with_server double-quote wrapper.

set -u

BASE="${QUICBAAS_REST_URL:-https://quicbaas-server:8443}"

for _ in $(seq 1 60); do
	W=$(curl -sk -o /dev/null -w '%{http_code}' -X POST \
		-H 'Content-Type: application/json' -d '{}' \
		"$BASE/api/v1/webauthn/registration/begin" || echo 000)
	P=$(curl -sk -o /dev/null -w '%{http_code}' -X POST \
		"$BASE/api/v1/iam/login/piv" || echo 000)
	case "$W-$P" in
	200-401 | 400-401 | 422-401)
		echo "quicbaasd login planes ready (webauthn=$W iam-piv=$P)"
		exit 0
		;;
	esac
	sleep 2
done

echo "quicbaasd login planes never became ready (webauthn=${W:-?} iam-piv=${P:-?})" >&2
exit 1
