# Web Console — API

> **Status: NORMATIVE** · Feature: `web-console` · Repo: `go-xkms` · Last verified: 2026-10-12

The console is a REST-only client. It never dials gRPC, QUIC, MCP, or the
Unix socket, and — despite `sdk/ts` shipping a WebSocket-capable SSH console
client (`ssh-console.ts`) for xkey's benefit — `web/app` imports none of it;
`grep` for `ssh-console` or `WebSocket` under `web/app/src` returns nothing.
Transport shapes for the underlying routes are described once in
[`../key-management/api.md`](../key-management/api.md) §"How the six
transports are shaped"; this page covers only the endpoints specific to the
console's own login/session/UI-mount concerns and the go-qrdb services the
console does not re-host.

## Capability discovery

`GET /api/v1/capabilities` — unauthenticated, `GroupRoot`:

```json
{"version": "...", "webauthn_enabled": true, "piv_login_enabled": false, "ui_enabled": true}
```

Deliberately coarse: only what a login screen needs to decide which
credential types to offer. The full capability map is authenticated-only,
at `/auth/me` below, so an anonymous caller cannot fingerprint which
optional subsystems (FROST, tenants, ...) this deployment
wired.

## Session plane

| Route | Auth | Purpose |
|---|---|---|
| `POST /api/v1/auth/login/piv` | public (requires `tls.client_auth`) | Exchange a verified client certificate for a token pair |
| `POST /api/v1/webauthn/login/begin` / `/finish` | public | WebAuthn login ceremony (`pkg/webauthn/http` mount) |
| `POST /api/v1/webauthn/registration/begin` / `/finish` | public | WebAuthn passkey enrolment |
| `POST /api/v1/auth/refresh` | public (refresh token in body) | Rotate the access/refresh pair |
| `GET /api/v1/auth/me` | session | Identity, RBAC `permissions` map, `capabilities` map |
| `GET /api/v1/auth/validate` | session | Lightweight boot-time session probe |
| `POST /api/v1/auth/logout` | session | Revoke the refresh token family |

`GET /api/v1/auth/me`'s `permissions` map is built from a fixed
`uiPermissionMatrix` of resource:action pairs, the pairs the console gates on.

## Navigation gates

Each sidebar entry in `navSections` (`web/app/src/lib/nav.ts:37`) carries an
optional `requires` (RBAC pair, checked against `permissions`) and an optional
`capability` (checked against `capabilities`), both from `GET /api/v1/auth/me`:

| Screen | Route | `requires` | `capability` |
|---|---|---|---|
| Dashboard | `#/dashboard` | — | — |
| Backends | `#/backends` | `backends:list` | — |
| Keys | `#/keys` | `keys:list` | — |
| FROST | `#/frost` | `keys:list` | `frost` |
| TPM Policies | `#/tpm/policies` | — | `tpm_policies` |
| Certificates | `#/certs` | `certs:list` | — |
| Certificate Authority | `#/ca` | — | `ca` |
| PIN | `#/pin` | `pin:read` | — |
| PIV | `#/piv` | `piv:read` | — |
| SSH | `#/ssh` | `ssh:read` | `ssh` |
| Passwords | `#/passwords` | `passwords:read` | `passwords` |
| OIDC Credentials | `#/oidc/credentials` | `oidc_credentials:list` | `oidc_credentials` |
| Platform Secrets | `#/platform` | — | `platform` |
| Users | `#/users` | `users:list` | — |
| Tenants | `#/tenants` | `tenants:list` | `tenants` |
| Settings | `#/settings` | — | — |

Signed out, the only routes are `#/login` and `#/register`
(`web/app/src/stores/router.svelte.ts:52`); an authenticated visitor sent to
either is redirected to `#/dashboard` (`web/app/src/App.svelte:79`).

## Screen → REST parity

Every other screen's REST surface is the same route table `xkmsctl`
drives, gated the same way. Columns: **REST**, the `xkmsctl` command group,
and the console screen.

| Feature area | REST | `xkmsctl` | Console screen |
|---|---|---|---|
| Health / status | `/health*` | `status` | Dashboard |
| Backends | `/api/v1/backends*` | `backends` | Backends |
| Keys (gen/list/rotate/delete) | `/api/v1/keys*` | `key` | Keys + Key detail |
| Sign / verify | `/api/v1/keys/{id}/sign\|verify` | `key sign\|verify` | Key detail → Sign, Verify |
| Encrypt / decrypt | `/api/v1/keys/{id}/encrypt\|decrypt\|encrypt-asym` | `key encrypt\|decrypt` | Key detail → Encrypt, Decrypt |
| Wrap / unwrap by ID | `/api/v1/keys/wrap-by-id`, `/unwrap-by-id` | `key wrap-by-id\|unwrap-by-id` | Key detail → Wrap |
| ECDH derivation | `/api/v1/keys/derive-ecdh` | `key derive-ecdh` | Key detail → Derive |
| Import ceremony | `/api/v1/keys/import-params`, `/wrap`, `/import` | `key import` | Keys → Import wizard |
| Wrapped export / copy | `/api/v1/keys/{id}/export`, `/keys/copy` | `key export\|copy` | Key detail → Transfer |
| Attest / export raw material | `/api/v1/attest`, `/keys/{id}/export-material` | `key attest\|export-material` | Key detail → Advanced |
| Certificates (+chain, TLS bundle) | `/api/v1/certs*`, `/tls/{id}` | `cert`, `tls` | Certificates |
| CA (issue/revoke/CRL/bundle) | `/api/v1/ca/*` | `ca` | Certificate Authority |
| CA TCG (EK/AK/enroll) | `/api/v1/ca/tcg/*` | `ca tcg` | CLI-only (device provisioning) |
| PIN | `/api/v1/pin/*` | `pin` | PIN |
| PIV | `/api/v1/piv/slots/*` | `piv` | PIV (slot view only; cert ops via CLI) |
| SSH keys | `/xkms/v1/ssh/keys*` | `ssh keys` | SSH (list/generate/delete only) |
| SSH known-hosts / authorized-keys | `/xkms/v1/ssh/known-hosts*`, `/authorized-keys*` | `ssh known-hosts`, `ssh authorized-keys` | CLI-only |
| TPM Policies | `/api/v1/tpm/*` | `tpm policy` | TPM Policies (create simple or with branches, description, verify per branch, update, revoke, auto-unseal, objects, delete, rotate authority) |
| FROST (keys only, not signing rounds) | `/api/v1/frost/keys*`, `/frost/verify` | `frost` | FROST |
| Users | `/api/v1/users*` | `user`, `admin` | Users |
| Tenants | `/api/v1/tenants/*` | `tenant` | Tenants |
| Passwords vault | `/api/v1/passwords/*` | `password` | Passwords |
| Platform secrets | `/api/v1/platform/secrets*` | `platform` | Platform Secrets |
| Backend credentials | `/credentials/*` | `credential` | CLI-only |
| Auth factors | none (go-qrdb `UserAuthFactorService`) | `auth factor` | CLI-only |
| Cluster | none (go-qrdb `AdminService`) | `cluster` | Dashboard card: "clustered" / "standalone" only |

## Cluster and auth factors are go-qrdb's

Cluster status, membership and per-user auth factors are go-qrdb services
(`AdminService`, `UserAuthFactorService`), registered on xkmsd's gRPC server
and Unix socket by `pkg/server/qrdb_control_plane.go`. xkms does not re-host
them over REST, so the console has no Cluster or Auth Factors page; use
`xkmsctl cluster` and `xkmsctl auth factor`. The dashboard's cluster card
reads the `cluster` capability flag from `GET /api/v1/auth/me`.

## Documented CLI-only (no console equivalent)

Unchanged from the underlying transport parity: `fido2 *` (USB CTAP2 —
console uses browser WebAuthn instead), `pkcs11 *` (local module probing),
`migrate *` (local backend-to-backend migration), `bootstrap
noise|dane|spki|direct` (offline trust math), `credential *` (same ceremony path), `ca tcg *` (device provisioning),
`key export-material` on hardware.

## Errors

Standard error mapping is the one shared REST surface uses
([`../key-management/api.md`](../key-management/api.md)); the console adds
no error vocabulary of its own. `pkg/webui`'s own failures
(`ErrNilAssets`, `ErrNilRouter`, `ErrInvalidPrefix`) are composition-time —
they fail server startup, not a request.
