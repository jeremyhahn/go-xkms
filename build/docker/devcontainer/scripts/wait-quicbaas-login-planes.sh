#!/bin/bash
# wait-quicbaas-login-planes.sh: block until the quicbaasd fixture's login planes serve.

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
