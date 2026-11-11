#!/usr/bin/env bash
# Run the WebAuthn browser suite; on failure print the xkmsd log (CA m2529).
#
# The suite runs inside the devcontainer and Playwright stops relaying the
# webServer's output once xkmsd is ready, so a server-side error (a ceremony's
# 500) never reached the CI job log. run-server.sh keeps xkmsd's full output
# in .runtime/xkmsd.log; when `npx playwright test` fails this prints its last
# lines and exits with Playwright's status. A passing run prints nothing extra.
set -uo pipefail

cd "$(dirname "$0")" || exit 1

LOG="./.runtime/xkmsd.log"
LINES=400

npx playwright test "$@"
rc=$?
if [ "$rc" -ne 0 ]; then
	echo
	if [ -f "$LOG" ]; then
		echo "===== WebAuthn browser suite failed (exit ${rc}): last ${LINES} lines of the xkmsd log (${LOG}) ====="
		tail -n "$LINES" "$LOG"
		echo "===== end of the xkmsd log ====="
	else
		echo "===== WebAuthn browser suite failed (exit ${rc}): no xkmsd log at ${LOG} ====="
	fi
fi
exit "$rc"
