# 2529: the WebAuthn browser suite keeps and prints the xkmsd log (CA m2529)

## Where xkmsd's log goes today

- `make integration-test-webauthn-browser` (Makefile:2606-2608) runs
  `npx playwright test` inside the devcontainer through `run_in_devcontainer`
  (`docker compose exec -T devcontainer bash -c "cd <repo> && ..."`); in CI the
  workspace is synced into the container, so files written there do not come
  back to the runner.
- Playwright's `webServer` block (`playwright.config.ts:52-61`) starts
  `bash ./run-server.sh` with `stdout: 'pipe'` and `stderr: 'pipe'`. The
  `[WebServer]` lines Playwright relays are the only copy of the log, and the
  CI log shows none after the server is ready.
- `run-server.sh` runs `xkmsd init` (its output to stderr), then `xkmsd` in the
  background with its stdout and stderr inherited from the script, i.e. the
  same Playwright pipes. Nothing is written to disk.
- `config.yaml` `logging:` sets `level: info`, `format: json` and no file
  output, so xkmsd logs to its standard streams only.

So the registration 500's Error line is lost: no file holds it and Playwright
does not relay it.

## Change

1. `run-server.sh` tees its whole output (build, `xkmsd init`, xkmsd, the
   barrier opening) to `.runtime/xkmsd.log`, truncated at each start. The
   Playwright pipes still get every line. `.runtime/` is git-ignored
   (`test/integration/webauthn-browser/.gitignore`).
2. `run-suite.sh` runs `npx playwright test`; when it fails it prints the last
   400 lines of `.runtime/xkmsd.log` under a header and exits with Playwright's
   status. On success it prints nothing extra. The Makefile recipe calls it
   (a script, because the recipe text passes through `bash -c "..."` in
   `run_in_devcontainer`, where `$?` would expand on the host).
3. Test: `test/scripts/webauthn-browser-suite.test.sh` runs `run-suite.sh`
   against a stub `npx` (failing and passing) and checks the output and the
   exit status; it joins the `test/scripts` list in the Makefile.

No workflow change: the log is printed by the command the job already runs,
so it lands in the job log. No product code change.

## Tests

- `bash test/scripts/webauthn-browser-suite.test.sh`
- `make -n integration-test-webauthn-browser` shows `run-suite.sh`
- shellcheck on the changed shell files; `make lint`
- The browser suite itself needs Docker: CI runs it.
