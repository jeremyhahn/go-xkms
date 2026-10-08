# Web Console Screens

The console is one Svelte 5 SPA (`web/app`) that runs three ways from a single
build: served by xkmsd at `/ui/`, in the Wails desktop shell against a remote
xkmsd, and in the desktop shell against an embedded engine on loopback. See
[running.md](running.md) for the run modes and [parity.md](parity.md) for how
each screen lines up with the REST API and `xkmsctl`.

Every screen is gated twice. An RBAC gate (`requires`) hides a nav entry the
identity has no permission for, and a capability gate (`capability`) hides one
the deployment never wired — a server built without FROST, or running without
an embedded qrdb node, simply has no such entry. Hiding is a convenience, not
the control: the server's RBAC decorators remain the enforcement authority and
every view renders the 403 it gets back.

## Navigation

| Section | Screen | Route | RBAC | Capability |
|---|---|---|---|---|
| Overview | Dashboard | `#/dashboard` | — | — |
| Overview | Backends | `#/backends` | `backends:list` | — |
| Keys & Crypto | Keys | `#/keys` | `keys:list` | — |
| Keys & Crypto | FROST | `#/frost` | `keys:list` | `frost` |
| Keys & Crypto | PCR Policies | `#/policies` | — | `policies` |
| Certificates & CA | Certificates | `#/certs` | `certs:list` | — |
| Certificates & CA | Certificate Authority | `#/ca` | — | `ca` |
| Security | Barrier & Seal | `#/barrier` | `seal:status` | — |
| Security | PIN | `#/pin` | `pin:read` | — |
| Security | PIV | `#/piv` | `piv:read` | — |
| Security | SSH | `#/ssh` | `ssh:use` | `ssh` |
| Security | Passwords | `#/passwords` | `passwords:read` | `passwords` |
| Security | Platform Secrets | `#/platform` | — | `platform` |
| Security | Init Ceremony | `#/ceremony` | — | `ceremony` |
| Identity & Access | Users | `#/users` | `users:list` | — |
| Identity & Access | Audit | `#/audit` | `audit:read` | `audit` |
| Identity & Access | Tenants | `#/tenants` | `tenants:list` | `tenants` |
| Identity & Access | Custodians | `#/custodians` | — | `custodians` |
| Identity & Access | Shares | `#/shares` | — | `shares` |
| Settings | Settings | `#/settings` | — | — |

Signed out, only two screens exist: Login (`#/login`) and Register
(`#/register`). Authentication is passwordless — passkeys (WebAuthn) and
PIV/mTLS client certificates. An authenticated visitor who navigates to either
is redirected to the dashboard.

## What each screen does

**Dashboard** — health, barrier state, backend summary, and cluster status,
each panel loading independently so one unavailable subsystem does not blank
the page.

**Backends** — the configured backends and their capabilities, including
whether each is hardware-backed.

**Keys** — the key lifecycle: list, generate, rotate, delete, and an import
wizard. Selecting a key opens a detail drawer with Overview, Sign, Verify,
Encrypt, Decrypt, Wrap, Derive, Transfer, and Advanced tabs; each tab is
present only when the identity holds the matching `keys:*` permission and the
key type supports the operation. Advanced covers attestation and raw key
material export, the latter gated on `keys:export` and warned as a secret.

**FROST** — threshold keys and signature verification. The signing rounds stay
on the CLI; see the note in [parity.md](parity.md).

**Certificates / Certificate Authority** — stored certificates and their
chains; CA issuance, revocation, and CRL generation. TCG device provisioning
(EK/AK) is CLI-only.

**Barrier & Seal** — seal status, unseal, and seal. Shamir initialisation and
rekey run through the CLI ceremony.

**PIN / PIV** — SO and user PIN management with lockout status; PIV slot
inspection.

**SSH** — stored SSH keys: list, generate, delete. The console deliberately
terminates no SSH session; see [parity.md](parity.md).

**Passwords / Platform Secrets** — the password vault (unlock, add, delete)
and platform-sealed secrets.

**Init Ceremony** — first-boot initialisation state and credential strategy.

**Users** — user lifecycle. Per-user auth factors are go-qrdb's
`UserAuthFactorService`, managed with `xkmsctl auth factor`.

**Audit** — the tamper-evident chain, filterable by actor, resource, action,
outcome, and time range, paged by cursor. The detail drawer shows the full
event including `prev_hash`.

**Tenants / Custodians / Shares** — tenant lifecycle, custodian groups and
share distribution, and submitted share status.

**Settings** — session identity, theme, and the deployment's capability flags.

## Dialogs

Every modal renders through `src/components/Modal.svelte`, which drives the
native `<dialog>` element so the browser supplies top-layer stacking, a focus
trap, and Escape-to-close rather than the app simulating them. Focus moves
into the dialog on open and returns to the invoking control on close.
