#!/bin/sh
# Entrypoint of the API suite's integration-tests service: unseals the
# xkms-server, then runs the service's command. Every Makefile runner replaces
# that command with its own, so the unseal lives here, where each one keeps
# it. unseal-server.sh leaves an already-unsealed server alone.
set -eu

echo "Unsealing the server..."
sh "$(dirname "$0")/unseal-server.sh"
exec "$@"
