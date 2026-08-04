# Live-backend Playwright tests

These tests drive the **real** xkey Wails app (backend + frontend) against a
**real** xkms-server. They are the end-to-end safety net for everything
the unit / mocked-UI tests cannot catch: Wails RPC wiring, native
dialogs, real file I/O, real TLS handshakes, and real bootstrap wire
format.

Unlike `tests/e2e/*.spec.ts`, which stub `window.go` via `addInitScript`
and run against `vite dev`, the tests here assume:

1. An **xkms-server** is reachable at `https://localhost:${XKMS_HOST_REST_PORT}`.
2. An **xkey Wails dev server** is reachable at `http://localhost:34115`.
3. The server's SPKI pin / Noise key / CA cert are exposed in the
   environment (populated by `make dev-server-up` via helper script).

## Running

### Why you must use `dev-browser-e2e`, not `dev-browser`

The xkey GUI resolves its bootstrap config through `os.UserConfigDir()` (on
Linux: `$XDG_CONFIG_HOME`, defaulting to `~/.config`) to find
`~/.config/xkey/gui.json`. This path is **outside** `XKEY_HOME`.

Running `make dev-browser` with only `XKEY_HOME` overridden still reads and
writes the developer's real `~/.config/xkey/gui.json`. If that file contains
`setup_complete=true` while the sandbox `XKEY_HOME` has no PINs, the app boots
into an App-Locked screen that no PIN can unlock — a corrupt, developer-data-
mutating state.

`make dev-browser-e2e` sets **both** `XKEY_HOME` and `XDG_CONFIG_HOME` to
isolated sandbox directories (`/tmp/xkey-e2e-home` and `/tmp/xkey-e2e-config`)
so neither your data directory nor your config file is ever touched.

Use `make dev-browser-e2e-clean` to wipe the sandbox before a run that needs
the first-run wizard (e.g. global-setup initialisation tests).

### Steps

From the repo root:

```shell
# Terminal 1: start the live kms server.
make dev-server-up
# Prints connection info; grab the SPKI pin + noise key from the output
# and export them (or set via env + restart the server):
export LIVE_XKMS_REST_URL=https://localhost:18443
export LIVE_XKMS_SPKI_PIN=<pin from dev-server-info>
export LIVE_XKMS_NOISE_ADDR=localhost:18445
export LIVE_XKMS_NOISE_KEY=<noise key from dev-server-info>
export LIVE_XKMS_CA_PEM=/tmp/xkms-dev-ca.crt

# Terminal 2: reset the e2e sandbox so the app boots into the wizard.
cd xkey && make dev-browser-e2e-clean

# Terminal 2 (continued): start xkey in hermetic browser mode.
make dev-browser-e2e

# Terminal 3: run the live Playwright tests.
cd xkey/frontend
BASE_URL=http://localhost:34115 \
  npx playwright test tests/e2e/live/ --reporter=list

# When done:
make dev-server-down
```

## Adding a new live test

1. Put the spec under `tests/e2e/live/<domain>.spec.ts`.
2. Call `requireLiveEnv(test)` at the top of the describe so tests skip
   cleanly when the live stack isn't present.
3. Use the helpers in `./helpers.ts` (sibling to this file) rather than
   re-rolling navigation logic.
4. Never mock `window.go` — that defeats the purpose of this tier.

## Scope

These tests cover the set of operations that *must* round-trip through
the real backend to be meaningful:

- Trust Store ↔ xkms-server bootstrap (Direct, SPKI, Noise, DANE)
- CA operations (issue, sign CSR, revoke, CRL)
- Key management against remote backends
- Admin backends list / status
- OIDC flows that require the server
- Custodian / Share / Tenant ceremonies

Purely local features (local FIDO2 virtual authenticator, TPM, local
password store, etc.) are covered by the mocked-UI tests and do not
need a live backend.
