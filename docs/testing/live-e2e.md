# Live-Backend E2E Testing

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: the live-backend Playwright tier (`xkey/frontend/tests/e2e/live/`) and the `dev-server-*` / `test-e2e-live` Make targets.

This document describes the end-to-end testing tier that exercises the
**real** xkey Wails app against a **real** xkms-server. It exists to
catch bugs that fall through every other tier: Wails RPC wiring, native
OS dialogs, real file I/O, TLS handshakes, and actual bootstrap wire
format.

> **Known gap — the dev server does not start today.** `dev-server-up` runs
> the `xkms-server` service of `test/integration/bootstrap/docker-compose.yml`,
> whose config (`scripts/generate-test-certs.sh`, written to
> `/etc/xkms/xkmsd.yaml`) has `auth.enabled: false` and no `ca` section.
> `xkmsd` refuses to start on any compliance gap (`cmd/xkmsd/main.go:170`),
> so the container never turns healthy until that config gains an
> authenticator and a CA (see the comment on the service in the compose file).

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
# Brings up the bootstrap compose's xkms-server, publishes its REST/TLS
# (8443) and Noise (8445) ports on ephemeral host ports, and prints the
# actual ports plus CA cert / SPKI pin / Noise key.
make dev-server-up

# Pin the host ports instead of taking ephemeral ones:
# XKMS_HOST_REST_PORT=8443 XKMS_HOST_NOISE_PORT=8445 make dev-server-up

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
| `make dev-server-up` | Start the `xkms-server` container, publish ports, wait up to 30 s for health, emit connection info (`Makefile:4723`) |
| `make dev-server-down` | Stop the stack and remove its volumes (`Makefile:4739`) |
| `make dev-server-info` | Re-print CA cert / SPKI pin / Noise key / xkey wiring hints |
| `make dev-server-logs` | Tail server logs |
| `cd xkey && make dev-browser` | Launch xkey in browser-accessible dev mode (:34115) |
| `make test-e2e-live` | Run the live Playwright suite; exports the `LIVE_XKMS_*` variables from the running container (`Makefile:4758`) |

## Writing a new live test

1. Create `xkey/frontend/tests/e2e/live/<operation>.spec.ts`.
2. `import { requireLiveEnv, waitForBackendReady, assertLiveWailsMode } from './helpers';`
3. In each test: call `requireLiveEnv()` to read the `LIVE_XKMS_*`
   variables and skip when they are not set (`live/helpers.ts:38`).
4. Use the normal helpers from `../helpers.ts` for navigation.
5. **Never** set `window.go` — if you do, you're writing a mocked-UI
   test, not a live-backend test. `assertLiveWailsMode` will catch this (`live/helpers.ts:70`).
6. Snapshot state before the operation (e.g., `TrustService.CertificateCount()`,
   `xkey/pkg/gui/services/trust_service.go:328`)
   and assert the delta, not the absolute value. The live backend may
   have state from prior runs.
7. Cover at minimum: happy path, one failure path (bad pin / wrong URL),
   and one idempotency case (re-running produces zero-added, not an
   error).

## Extending for mTLS / admin flows

The current dev server config (`test/integration/bootstrap/scripts/generate-test-certs.sh`)
has `auth: enabled: false` (line 195). For operations that require authenticated
admin access (CA issue, key generate, admin backends), we need to:

1. Extend `generate-test-certs.sh` to also produce an admin client
   cert signed by the test CA and its private key.
2. Flip `auth.enabled: true` and `tls.client_auth: require_and_verify`
   in the generated `xkmsd.yaml`.
3. Plumb the admin client cert/key into the xkey GUI config (Settings →
   Server → mTLS Client Cert / Key) when running `make dev-browser`.

This is tracked as a separate task — needed before the CA / Keys /
Admin / Tenant rows of the parity matrix can be tested.

## Known gaps

- **DANE**: the CoreDNS fixture does not produce DNSSEC AD-validated
  responses. `TrustStrapImportRequest` does take a resolver override
  (`DNSServer`, `xkey/pkg/gui/services/trust_service.go:447`), but without
  AD-validated answers the live tier cannot pass DANE. DANE coverage stays at the devcontainer integration
  tier via `test/integration/bootstrap/bootstrap_test.go`.
- **mTLS admin flows**: see section above.
- **Dev server startup**: see the known gap at the top of this page.

## Parity matrix

See [parity-matrix.md](parity-matrix.md) for the full inventory of
server-backed operations, their GUI / CLI / xkmsctl entry points, and
their live-test status.
