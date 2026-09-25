# Web Console — User Guide

> **Status: NORMATIVE** · Feature: `web-console` · Repo: `go-xkms` · Last verified: 2026-09-24

## What it is

A browser-based management console for a running `xkmsd`, and a desktop
app (`xkms-console`) that either points at a remote `xkmsd` or boots a
complete local KMS in-process. Login is passwordless: a passkey (WebAuthn)
or a PIV/mTLS client certificate — there is no password.

## Server-hosted: the common case

```sh
xkmsctl init            # provisions CA + admin mTLS + an encrypted barrier
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

The startup log line `mounted SPA web UI prefix=/ui/` confirms the mount.

## If the daemon refuses to start

`xkmsd` is secure-by-default: it refuses to start when encryption-at-rest
(the barrier), TLS, authentication, or a CA is missing — those controls are
required by FedRAMP/PCI-DSS/HIPAA — and the UI never comes up in that case.
The log names the exact gap, for example:

```
gaps: ["encryption-at-rest disabled (barrier.enabled=false): data is stored in plaintext",
       "authentication disabled (auth.enabled=false): access is anonymous"]
```

Fix the named control (or run `xkmsctl init` to provision it); there is no
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
barrier status/unseal/seal, PIN and PIV slot inspection, stored SSH keys
(no terminal — see below), the password vault, platform secrets, users and
per-user auth-factor enrolment, the tamper-evident audit log, tenants,
custodian groups and share distribution, and read-only cluster status
(currently non-functional — see below).

### Navigation

| Section | Screen | Route |
|---|---|---|
| Overview | Dashboard, Backends | `#/dashboard`, `#/backends` |
| Keys & Crypto | Keys, FROST, PCR Policies | `#/keys`, `#/frost`, `#/policies` |
| Certificates & CA | Certificates, Certificate Authority | `#/certs`, `#/ca` |
| Security | Barrier & Seal, PIN, PIV, SSH, Passwords, Platform Secrets, Init Ceremony | `#/barrier`, `#/pin`, `#/piv`, `#/ssh`, `#/passwords`, `#/platform`, `#/ceremony` |
| Identity & Access | Users, Auth Factors, Audit, Tenants, Custodians, Shares | `#/users`, `#/factors`, `#/audit`, `#/tenants`, `#/custodians`, `#/shares` |
| Cluster | Cluster | `#/cluster` |
| Settings | Settings | `#/settings` |

Every nav entry is gated twice: an RBAC gate hides an entry the identity
has no permission for, and a capability gate hides one the deployment never
wired. Hiding is a convenience — the server's own RBAC decorators are the
enforcement authority, and any view you reach anyway (a stale link, a typed
hash route) still renders the 403 it gets back.

**Two entries never light up today, for anyone:** Audit and Auth Factors.
This is a server-side bookkeeping gap (the permission pairs their nav gate
checks are never included in what `/api/v1/auth/me` reports), not a
permissions problem on your account — see
[engineering.md](engineering.md) §"Known gaps". Both features work fully
if you navigate to them directly (`#/audit`, `#/factors`); only the
sidebar entry point is affected.

**Cluster is currently non-functional.** Its sidebar entry is always
hidden, and even reached directly its two REST calls 404 — the server has
no `/api/v1/cluster/status` or `/members` route. Use `xkmsctl cluster` for
cluster membership and status today.

## Things the console deliberately does not do

- **No SSH terminal.** The SSH screen manages stored keys only; `xkmsd`
  never dials out and proxies a shell on any transport. Use the **xkey**
  desktop client against this server as a backend for an interactive
  session — the terminal runs on your machine and the private key never
  leaves the vault.
- **No FROST signing rounds.** Generate, list, delete threshold keys and
  verify finished signatures here; the three-round signing ceremony
  coordinates separate share-holders through `xkmsctl frost`.
- **No Shamir init or rekey.** `xkmsctl barrier init-shamir` / `rekey` are
  CLI ceremonies by design — the shares are printed once, to a terminal,
  never round-tripped through a browser session.
- **No cluster membership changes.** `xkmsctl cluster add/remove` only —
  and today, no cluster reads either (see above).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `https://host:8443/ui/` 404s | Binary built without the `ui` tag | Rebuild with `make build-ui` |
| Daemon exits at startup with a `gaps: [...]` log line | Secure-by-default refused an insecure config | Fix the named control, or run `xkmsctl init` |
| Login screen offers no passkey option | `webauthn_enabled: false` in `/api/v1/capabilities` | The server has no WebAuthn RP configured |
| Login screen offers no certificate option | `piv_login_enabled: false` | `auth.piv_login.enabled` is off, or `tls.client_auth` does not request client certs |
| Audit or Auth Factors never appear in the sidebar | Known server-side gap, not a permissions problem | Navigate to `#/audit` / `#/factors` directly; both work |
| Cluster screen is blank or errors | No REST route exists yet | Use `xkmsctl cluster status` / `add` / `remove` |
| Desktop app: "remote mode requires XKMS_SERVER_URL or a saved bookmark" | Neither set | Set `XKMS_SERVER_URL`, or save a bookmark from inside the app once connected |
| Desktop standalone: nothing loads | `XKMS_CONFIG` config itself fails secure-by-default validation | Same fix as the server-hosted refusal above — the standalone engine is the same `pkg/server.Server` |

## Where to go next

- Every screen's REST/CLI equivalent: [api.md](api.md)
- What's actually wired under the hood, and the two open gaps: [engineering.md](engineering.md)
- Build and env-var reference: [cli.md](cli.md)
