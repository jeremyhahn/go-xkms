# xKMS Web Console

The web console is a single Svelte 5 SPA that manages a running `xkmsd`
server. It is served three ways from one codebase:

1. **Server-hosted** — embedded in `xkmsd` and served at `/ui/` when the
   binary is built with the `ui` tag.
2. **Desktop (remote)** — the Wails shell in `web/desktop/` pointed at a
   remote `xkmsd`.
3. **Desktop (standalone)** — the Wails shell boots the engine in-process on
   a loopback-only REST listener with a per-launch token (the "MS Access"
   model).

The data plane is REST in every mode. Authentication is **passwordless**:
WebAuthn passkeys and PIV / mTLS client certificates only.

## Layout

| Path | What |
|------|------|
| `web/app/` | The SPA (Svelte 5 + Vite 6 + Tailwind 4 + daisyUI) |
| `web/embed.go` | `//go:build ui` embed of `web/dist` for `xkmsd` |
| `web/desktop/` | Wails v2 desktop shell (own Go module) |
| `sdk/ts/` | `@go-xkms/sdk` — the framework-free REST + WebSocket client |
| `sdk/ts/svelte-auth/` | `@go-xkms/svelte-auth` — shared passwordless login components |
| `pkg/webui/` | Router-agnostic SPA file server + chi mount |
| `pkg/server/loopback/` | Loopback engine launcher for desktop standalone |

## Documentation

| Page | What |
|------|------|
| [running.md](running.md) | Run modes, URLs, and the secure-by-default startup rules |
| [screens.md](screens.md) | Every screen, its route, and its RBAC / capability gates |
| [parity.md](parity.md) | The authoritative REST ↔ `xkmsctl` ↔ console matrix, plus what is deliberately CLI-only |
| [testing.md](testing.md) | The unit, component, and two-tier Playwright suites |

## Building

```sh
make build-web     # build @go-xkms/sdk, the SPA, stage dist into the embeds
make build-ui      # build xkmsd with the embedded UI (ui build tag)
make dev-web       # Vite dev server, proxying to XKMS_DEV_API (default :8443)
make test-web      # type-check + unit tests for sdk/ts, svelte-auth, web/app
make coverage-web  # coverage for all three web packages
```

`make test-web` runs under coverage so the 90% thresholds in each vitest
config gate the build, and it is part of `make test` — the web suites fail CI
the same way the Go ones do.

`make build-web` copies the built `dist/` into both `web/dist` (the `xkmsd`
embed) and `web/desktop/frontend/dist` (the Wails embed).

## Running the server-hosted UI

See [running.md](running.md). The console is always served over TLS with a
certificate minted by the embedded CA. `xkmsd` **refuses to start without a
secure configuration** by design (FedRAMP / PCI-DSS / HIPAA); if it refuses,
the log names the exact control that is switched off. Both
`configs/xkmsd-local.yaml` and an `xkmsctl init`-provisioned deployment start
with no extra flags.

## Feature parity

The console aims for parity with `xkmsctl` over the server API surface. The
authoritative matrix is [parity.md](parity.md). Operations that are inherently
local to the machine running the CLI (USB CTAP2, local PKCS#11 module probing,
offline bootstrap math, officer claim-share) are documented CLI-only; the
console offers browser-native equivalents where they exist (WebAuthn instead
of USB FIDO2).
