# Web Console — User Guide

> **Status: NORMATIVE** · Feature: `web-console` · Repo: `go-xkms` · Last verified: 2026-10-12

## What it is

A browser-based management console for a running `xkmsd`, and a desktop
app (`xkms-console`) that either points at a remote `xkmsd` or boots a
complete local KMS in-process. Login is passwordless: a passkey (WebAuthn)
or a PIV/mTLS client certificate — there is no password.

## Server-hosted: the common case

```sh
xkmsd init              # provisions CA + admin mTLS + an encrypted barrier
xkmsd -c /etc/xkms/xkmsd.yaml
```

Browse to `https://<host>:8443/ui/`. Sign in with a passkey (enroll one
first through the Register screen or `xkmsctl`) or a PIV/mTLS client
certificate.

For local development, `xkmsd -c configs/xkmsd-local.yaml` needs no flags:
that config already turns on TLS with a CA-minted certificate,
`auth.type: adaptive` (anonymous only until the first user is provisioned,
enforced after), and an encrypted barrier with a development passphrase
that auto-unseals at boot.

**Prerequisites for the UI to actually be served:**

- The `xkmsd` binary must be built with the `ui` tag (`make build-ui`). A
  plain build serves the API only — the embed stub reports no UI and the
  mount is skipped.
- `protocols.rest: true` and a free REST port (default `8443`).
- `ui.enabled` is true by default; nothing to set unless you want it off.

```sh
curl -sk https://localhost:8443/api/v1/capabilities
# {"version":"...","webauthn_enabled":true,"piv_login_enabled":false,"ui_enabled":true}

curl -sko /dev/null -w '%{http_code}\n' https://localhost:8443/ui/   # 200
```

The startup log line `mounted SPA web UI prefix=/ui/` confirms the mount
(`pkg/webui/spa.go:109`).

## Configuration

```yaml
ui:
  enabled: true          # omitted means enabled; only an explicit false turns it off
  path_prefix: "/ui/"    # empty selects /ui/
  redirect_root: false   # true redirects GET / to the UI prefix

cors:                    # only for a browser served cross-origin; same-origin needs none
  enabled: false
  allowed_origins: []    # exact scheme://host[:port] origins
  allow_credentials: false
  max_age_seconds: 3600  # <= 0 selects 3600

auth:
  piv_login:             # POST /api/v1/auth/login/piv
    enabled: false       # needs tls.client_auth to request client certs
    trusted_issuers: []  # optional issuer-DN allowlist (exact match)
    attestation_roots: /etc/xkms/piv-attestation-root.pem  # required unless allow_unattested
    attestation_intermediates: []
    allow_unattested: false  # true accepts unattested keys; token records attest_level "unattested"; not with attestation_roots
  session:
    access_token_ttl: "15m"
    refresh_token_ttl: "8h"
    login_rate_per_min: 10   # 0 selects 10
```

Source: `UIConfig` (`pkg/config/config.go:612`), `CORSConfig`
(`pkg/config/config.go:594`), `PIVLoginConfig` (`pkg/config/config.go:451`),
`SessionConfig` (`pkg/config/config.go:479`). Startup refuses
`attestation_roots` together with `allow_unattested`
(`pkg/config/config.go:1651`).

## If the daemon refuses to start

`xkmsd` is secure-by-default: it refuses to start when encryption-at-rest
(the barrier), TLS, authentication, or a CA is missing — those controls are
required by FedRAMP/PCI-DSS/HIPAA — and the UI never comes up in that case.
The log names the exact gap, for example:

```
gaps: ["encryption-at-rest disabled (barrier.enabled=false): data is stored in plaintext",
       "authentication disabled (auth.enabled=false): access is anonymous"]
```

Fix the named control (or run `xkmsd init` to provision it); there is no
flag to force past the gate. Each gap maps to a config section:
`barrier.enabled`, `auth.enabled`/`auth.type`, `tls.enabled`, the `ca` block.

## Desktop app

```sh
cd web/desktop && go build -tags desktop -o xkms-console .
```

**Remote mode** — manage an existing `xkmsd`:

```sh
XKMS_DESKTOP_MODE=remote XKMS_SERVER_URL=https://kms.example.com:8443 ./xkms-console
```

Leaving `XKMS_SERVER_URL` unset falls back to the first saved bookmark
(managed from inside the running app).

**Standalone mode** — a complete local KMS, no separate daemon:

```sh
XKMS_DESKTOP_MODE=standalone XKMS_CONFIG=/etc/xkms/xkmsd.yaml ./xkms-console
```

This boots the real server engine in-process on a loopback-only listener
with a bearer token generated fresh for that launch — it is off-box
unreachable by construction, not by configuration. Close the app and the
token, and the engine, are gone.

## What you can do from the console

The full nav map is below; broad strokes: key lifecycle (generate/rotate/delete/sign/verify/encrypt/decrypt/
wrap/derive/transfer/attest), certificates and CA issuance/revocation/CRL,
PIN and PIV slot inspection, stored SSH keys
(no terminal — see below), the password vault, platform secrets, users and
tenants. The dashboard shows whether the deployment is clustered.

### Navigation

| Section | Screen | Route |
|---|---|---|
| Overview | Dashboard, Backends | `#/dashboard`, `#/backends` |
| Keys & Crypto | Keys, FROST, TPM Policies | `#/keys`, `#/frost`, `#/tpm/policies` |
| Certificates & CA | Certificates, Certificate Authority, TCG Certificates | `#/certs`, `#/ca`, `#/ca/tcg` |
| Security | PIN, PIV, SSH, Passwords, OIDC Credentials, Platform Secrets | `#/pin`, `#/piv`, `#/ssh`, `#/passwords`, `#/oidc/credentials`, `#/platform` |
| Identity & Access | Users, Tenants | `#/users`, `#/tenants` |
| Settings | Settings | `#/settings` |

Every nav entry is gated twice: an RBAC gate hides an entry the identity
has no permission for, and a capability gate hides one the deployment never
wired. Hiding is a convenience — the server's own RBAC decorators are the
enforcement authority, and any view you reach anyway (a stale link, a typed
hash route) still renders the 403 it gets back.

Cluster membership and status, and per-user auth factors, are go-qrdb's
services and have no console page: use `xkmsctl cluster` and
`xkmsctl auth factor`.

## Things the console deliberately does not do

- **No SSH terminal.** The SSH screen manages stored keys only; `xkmsd`
  never dials out and proxies a shell on any transport. Use the **xkey**
  desktop client against this server as a backend for an interactive
  session — the terminal runs on your machine and the private key never
  leaves the vault.
- **No FROST signing rounds.** Generate, list, delete threshold keys and
  verify finished signatures here; the three-round signing ceremony
  coordinates separate share-holders through `xkmsctl frost`.
- **No barrier, audit, custodian or share screens.** Those surfaces are go-qrdb's and xkms does not re-expose them.
- **No cluster status, membership or auth-factor management.** Those are
  go-qrdb services; use `xkmsctl cluster` and `xkmsctl auth factor`.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `https://host:8443/ui/` 404s | Binary built without the `ui` tag | Rebuild with `make build-ui` |
| Daemon exits at startup with a `gaps: [...]` log line | Secure-by-default refused an insecure config | Fix the named control, or run `xkmsd init` |
| Login screen offers no passkey option | `webauthn_enabled: false` in `/api/v1/capabilities` | The server has no WebAuthn RP configured |
| Login screen offers no certificate option | `piv_login_enabled: false` | `auth.piv_login.enabled` is off, or `tls.client_auth` does not request client certs |
| Desktop app: "remote mode requires XKMS_SERVER_URL or a saved bookmark" | Neither set | Set `XKMS_SERVER_URL`, or save a bookmark from inside the app once connected |
| Desktop standalone: nothing loads | `XKMS_CONFIG` config itself fails secure-by-default validation | Same fix as the server-hosted refusal above — the standalone engine is the same `pkg/server.Server` |

## Where to go next

- Every screen's REST/CLI equivalent: [api.md](api.md)
- What's actually wired under the hood, and the two open gaps: [engineering.md](engineering.md)
- Build and env-var reference: [cli.md](cli.md)
