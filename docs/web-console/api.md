# Web Console — API

> **Status: NORMATIVE** · Feature: `web-console` · Repo: `go-xkms` · Last verified: 2026-09-30

The console is a REST-only client. It never dials gRPC, QUIC, MCP, or the
Unix socket, and — despite `sdk/ts` shipping a WebSocket-capable SSH console
client (`ssh-console.ts`) for xkey's benefit — `web/app` imports none of it;
`grep` for `ssh-console` or `WebSocket` under `web/app/src` returns nothing.
Transport shapes for the underlying routes are described once in
[`../key-management/api.md`](../key-management/api.md) §"How the six
transports are shaped"; this page covers only the endpoints specific to the
console's own login/session/UI-mount concerns and corrects one existing
claim about the Cluster screen.

## Capability discovery

`GET /api/v1/capabilities` — unauthenticated, `GroupRoot`:

```json
{"version": "...", "webauthn_enabled": true, "piv_login_enabled": false, "ui_enabled": true}
```

Deliberately coarse: only what a login screen needs to decide which
credential types to offer. The full capability map is authenticated-only,
at `/auth/me` below, so an anonymous caller cannot fingerprint which
optional subsystems (FROST, tenants, custodians, ...) this deployment
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
`uiPermissionMatrix` of resource:action pairs — see
[engineering.md](engineering.md) §"Known gaps" for the two pairs
(`audit:read`, `users:read`) that are real, enforced permissions but are
absent from that matrix, so their nav entries never light up even for an
identity that holds them.

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
| Barrier (status/unseal/seal/rekey/recovery) | `/api/v1/barrier/*` | `barrier` | Barrier & Seal |
| PIN | `/api/v1/pin/*` | `pin` | PIN |
| PIV | `/api/v1/piv/slots/*` | `piv` | PIV (slot view only; cert ops via CLI) |
| SSH keys | `/xkms/v1/ssh/keys*` | `ssh keys` | SSH (list/generate/delete only) |
| SSH known-hosts / authorized-keys | `/xkms/v1/ssh/known-hosts*`, `/authorized-keys*` | `ssh known-hosts`, `ssh authorized-keys` | CLI-only |
| TPM Policies | `/api/v1/tpm/*` | `tpm policy` | TPM Policies (create simple or with branches, description, verify per branch, update, revoke, auto-unseal, objects, delete, rotate authority) |
| FROST (keys only, not signing rounds) | `/api/v1/frost/keys*`, `/frost/verify` | `frost` | FROST |
| Audit log | `/api/v1/audit/` | `audit query` | Audit — see the permission-matrix gap above |
| Users | `/api/v1/users*` | `user`, `admin` | Users |
| Auth factors | `/api/v1/factors/*` | `auth factor` | Auth Factors — see the permission-matrix gap above |
| Tenants | `/api/v1/tenants/*` | `tenant` | Tenants |
| Custodians | `/api/v1/custodian/groups/*` | `custodian` | Custodians |
| Shares | `/api/v1/shares/*` | `share` | Shares |
| Passwords vault | `/api/v1/passwords/*` | `password` | Passwords |
| Platform secrets | `/api/v1/platform/secrets*` | `platform` | Platform Secrets |
| Init / ceremony | `/api/v1/init/*`, `/credentials/*` | `init`, `credential` | Init & Ceremony (status only) |
| Cluster | none (see below) | `cluster` | Cluster — **broken**, see below |

## Cluster: documented as read-only, actually unreachable

Earlier documentation described the Cluster screen as "read-only; mutations
go through `xkmsctl cluster add/remove`". That undersold the gap: **no
`/api/v1/cluster/*` route exists at all**, read or write. Verified directly
against `pkg/api/rest/routes.go` (the file's own comment calls it the
single source of truth for the REST surface) — grepping the whole
non-test tree for `/api/v1/cluster` turns up exactly one match,
`clustercapkg.SecretDeliveryPath = "/api/v1/cluster/secret"`
(`pkg/trust/clusterca/secret_delivery.go`), an unrelated CA-secret-delivery
endpoint, not membership or status. `sdk/ts/src/clients/cluster.ts` and
`web/app/src/views/ClusterView.svelte` call `GET /api/v1/cluster/status`
and `GET /api/v1/cluster/members` regardless; both 404 against the real
server. The real cluster control plane (status, peers, membership
add/remove) is gRPC-only, served on the Unix socket
(`pkg/server/qrdb_control_plane.go`), which is what `xkmsctl cluster`
actually dials — REST was never wired for it. See
[engineering.md](engineering.md) §"Known gaps" for the companion nav-gate
gap that independently hides the screen's sidebar entry.

## Documented CLI-only (no console equivalent)

Unchanged from the underlying transport parity: `fido2 *` (USB CTAP2 —
console uses browser WebAuthn instead), `pkcs11 *` (local module probing),
`migrate *` (local backend-to-backend migration), `bootstrap
noise|dane|spki|direct` (offline trust math), `init claim-share` / `init
officer register` / `enroll-external-officer` (mTLS-ceremony-bound),
`credential *` (same ceremony path), `ca tcg *` (device provisioning),
`key export-material` on hardware.

## Errors

Standard error mapping is the one shared REST surface uses
([`../key-management/api.md`](../key-management/api.md)); the console adds
no error vocabulary of its own. `pkg/webui`'s own failures
(`ErrNilAssets`, `ErrNilRouter`, `ErrInvalidPrefix`) are composition-time —
they fail server startup, not a request.
