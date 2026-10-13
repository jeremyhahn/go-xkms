# ACME Client GUI

> **Status: REFERENCE** · Last verified: 2026-10-12
> Legacy, unabsorbed notes on the `trusted-acme-client` desktop GUI (`pkg/acme/gui/client`, `pkg/acme/web/packages/client`).

The ACME client GUI is a Wails v2 desktop window over the client SPA. It
covers account management, the certificate lifecycle (request, renew, revoke,
deploy) and TPM device enrollment and attestation. There is no auto-renewal
or configuration view. Renewal is set per certificate in the client YAML
config; see [configuration.md](configuration.md).

## Launch

```bash
go build -tags gui -o bin/trusted-acme-client ./cmd/acme-client
./bin/trusted-acme-client       # no subcommand opens the window
```

`cmd/acme-client/serve.go` is also `gui`-tagged. Its `serve` subcommand
serves the same client router over TCP/TLS instead of in a window
(`cmd/acme-client/serve.go:96`).

## Window defaults (`pkg/acme/gui/client/config.go:17-21`)

| Property | Value |
|----------|-------|
| Title | Trusted ACME Client |
| Size | 1024 x 768 |
| Min size | 800 x 600 |
| Linux program name | `trusted-acme-client` (`pkg/acme/gui/client/app.go:93`) |

## Navigation (`App.svelte`, sidebar title "ACME Client")

| View | Description |
|------|-------------|
| Dashboard | Account and certificate counts |
| Accounts | Configured ACME accounts, remove |
| Certificates | Certificate specs, filtered by account; request, renew, revoke, deploy |
| Register | Add an account (directory, email, key, optional EAB) |
| Request Cert | Request a certificate for a configured spec |
| Renew Cert | Renew a configured spec |
| Revoke Cert | Revoke a configured spec with a reason code |
| Device Enroll | TPM device enrollment |
| Device Attest | TPM device attestation |
| Challenges | Read-only descriptions of the challenge types |
| Settings | Theme (Light/Dark/System) and the API base URL |

## Related documentation

- [Views reference](views.md)
- [Configuration](configuration.md)
- [Challenge types](challenge-types.md)
- [Embedded API reference](api.md)
