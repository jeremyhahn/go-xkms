# Live-Backend E2E Testing

This document describes the end-to-end testing tier that exercises the
**real** xkey Wails app against a **real** xkms-server. It exists to
catch bugs that fall through every other tier: Wails RPC wiring, native
OS dialogs, real file I/O, TLS handshakes, and actual bootstrap wire
format.

## Testing tiers at a glance

| Tier | What it tests | Where |
|---|---|---|
| Go unit | Service methods as functions, in-memory | `xkey/pkg/gui/services/*_test.go` |
| Go httptest integration | Wire format against synthetic server | `xkey/pkg/gui/services/*_integration_test.go` |
| Devcontainer integration | Service methods against real xkms-server | `xkey/test/integration/*/` |
| Mocked-UI Playwright | Svelte DOM with injected `window.go` stubs | `xkey/frontend/tests/e2e/*.spec.ts` |
| **Live-backend Playwright** | Real Wails + real xkms-server | `xkey/frontend/tests/e2e/live/` |

Every tier above the live-backend tier stubs something important.
The live tier is the only tier that proves the full chain actually works.

## Three-terminal workflow

From the repo root:

```shell
# ── Terminal 1: start the xkms-server ──
# Brings up a docker-compose xkms-server, publishes 8443 (REST/TLS) and
# 8445 (Noise) to host, and prints CA cert / SPKI pin / Noise key.
make dev-server-up

# Ports can be overridden if 8443/8445 are taken:
# XKMS_HOST_REST_PORT=18443 XKMS_HOST_NOISE_PORT=18445 make dev-server-up

# ── Terminal 2: start xkey in Wails dev (browser) mode ──
# Serves the app on http://localhost:34115 for Playwright to connect to.
cd xkey && make dev-browser

# ── Terminal 3: run live Playwright tests ──
make test-e2e-live
```

When finished:

```shell
make dev-server-down
```

## Dev server management

| Target | Purpose |
|---|---|
| `make dev-server-up` | Start `xkms-server` container + publish ports; emit connection info |
| `make dev-server-down` | Stop container + remove volumes |
| `make dev-server-info` | Re-print CA cert / SPKI pin / Noise key / xkey wiring hints |
| `make dev-server-logs` | Tail server logs |
| `cd xkey && make dev-browser` | Launch xkey in browser-accessible dev mode (:34115) |
| `make test-e2e-live` | Run the live Playwright suite (auto-pulls env vars from the running container) |

## Writing a new live test

1. Create `xkey/frontend/tests/e2e/live/<operation>.spec.ts`.
2. `import { requireLiveEnv, waitForBackendReady, assertLiveWailsMode } from './helpers';`
3. In each test: call `requireLiveEnv()` to pull credentials + skip when
   the live stack is not configured.
4. Use the normal helpers from `../helpers.ts` for navigation.
5. **Never** set `window.go` — if you do, you're writing a mocked-UI
   test, not a live-backend test. `assertLiveWailsMode` will catch this.
6. Snapshot state before the operation (e.g., `TrustService.CertificateCount()`)
   and assert the delta, not the absolute value. The live backend may
   have state from prior runs.
7. Cover at minimum: happy path, one failure path (bad pin / wrong URL),
   and one idempotency case (re-running produces zero-added, not an
   error).

## Extending for mTLS / admin flows

The current dev server config (`test/integration/bootstrap/scripts/generate-test-certs.sh`)
has `auth: enabled: false`. For operations that require authenticated
admin access (CA issue, key generate, admin backends), we need to:

1. Extend `generate-test-certs.sh` to also produce an admin client
   cert signed by the test CA and its private key.
2. Flip `auth.enabled: true` and `tls.client_auth: require_and_verify`
   in the generated `xkmsd.yaml`.
3. Plumb the admin client cert/key into the xkey GUI config (Settings →
   Server → mTLS Client Cert / Key) when running `make dev-browser`.

This is tracked as a separate task — needed before the CA / Keys /
Admin / Custodian / Tenant rows of the parity matrix can be tested.

## Known gaps

- **DANE**: the CoreDNS fixture does not produce DNSSEC AD-validated
  responses and `TrustService.ImportFromTrustStrap` does not expose a
  resolver override. DANE coverage stays at the devcontainer integration
  tier via `test/integration/bootstrap/bootstrap_test.go`.
- **mTLS admin flows**: see section above.

## Parity matrix

See `docs/testing/parity-matrix.md` for the full inventory of
server-backed operations, their GUI / CLI / xkmsctl entry points, and
their live-test status.
