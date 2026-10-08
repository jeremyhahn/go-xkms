# CLI ↔ Web Console Parity

Authoritative parity matrix over the `xkmsd` server API surface. Columns:
**REST** (the endpoint group), **CLI** (`xkmsctl` command), **Web** (console
screen). ✓ = present; CLI-only = documented local/offline operation with no
server surface.

| Feature area | REST | CLI (`xkmsctl`) | Web console |
|---|---|---|---|
| Health / status | `/health*` | `status` | Dashboard |
| Backends | `/backends` | `backends` | Backends |
| Keys (gen/list/rotate/delete) | `/keys*` | `key` | Keys + Key detail |
| Sign / verify | `/keys/{id}/sign\|verify` | `key sign\|verify` | Key detail → Sign, Verify |
| Encrypt / decrypt | `/keys/{id}/encrypt\|decrypt\|encrypt-asym` | `key encrypt\|decrypt` | Key detail → Encrypt, Decrypt (AEAD or RSA-OAEP, chosen by key type) |
| Wrap / unwrap by ID | `/keys/wrap-by-id`, `/keys/unwrap-by-id` | `key wrap-by-id\|unwrap-by-id` | Key detail → Wrap |
| ECDH derivation | `/keys/derive-ecdh` | `key derive-ecdh` | Key detail → Derive (accepts PEM or base64 DER) |
| Import ceremony | `/keys/import-params`, `/keys/wrap`, `/keys/import` | `key import` | Keys → **Import** (3-step wizard) |
| Wrapped export / copy | `/keys/{id}/export`, `/keys/copy` | `key export\|copy` | Key detail → Transfer |
| Attest / export raw material | `/attest`, `/keys/{id}/material` | `key attest\|export-material` | Key detail → Advanced |
| Certificates (+chain, TLS bundle) | `/certs*`, `/tls/{id}` | `cert`, `tls` | Certificates |
| CA (issue/revoke/CRL/bundle) | `/ca/*` | `ca` | Certificate Authority |
| CA TCG (EK/AK/enroll) | `/ca/tcg/*` | `ca tcg` | CLI-only (device provisioning) |
| Barrier / seal | `/barrier/*` | `barrier`, `seal`/`unseal` | Barrier & Seal (unseal/seal; shamir/rekey via CLI) |
| PIN | `/pin/*` | `pin` | PIN |
| PIV | `/piv/slots/*` | `piv` | PIV (slot view; cert ops via CLI) |
| SSH keys | `/xkms/v1/ssh/*` | `ssh keys` (incl. `import`) | SSH (list/generate/delete) |
| SSH known hosts | `/xkms/v1/ssh/known-hosts/*` | `ssh known-hosts` (add/list/remove/verify) | CLI-only (host-key pinning) |
| SSH authorized keys | `/xkms/v1/ssh/authorized-keys/*` | `ssh authorized-keys` (add/get/list/remove/emit/verify) | CLI-only |
| Policies (PCR) | `/policies/*` | `policy` | PCR Policies |
| FROST threshold keys | `/api/v1/frost/*` | `frost` | FROST (list/generate/delete/verify) |
| Audit log | `/api/v1/audit` | `audit query` | Audit (filter + cursor paging) |
| Users | `/api/v1/users/*` | `user`, `admin` | Users |
| Auth factors (N-factor) | none — go-qrdb `UserAuthFactorService` | `auth factor` | CLI-only |
| Tenants | `/tenants/*` | `tenant` | Tenants |
| Custodians | `/custodian/groups/*` | `custodian` | Custodians |
| Shares | `/shares/*` | `share` (submit/list/get/delete/status) | Shares |
| Passwords vault | `/passwords/*` | `password` | Passwords |
| Platform secrets | `/platform/secrets/*` | `platform` | Platform Secrets |
| Init / ceremony | `/init/*`, `/credentials/*` | `init`, `credential` (submit/list/strategy) | Init & Ceremony (status) |
| Security Officer enrolment | `/init/officer/*`, `/init/enroll-external-officer` | `init officer register\|status`, `init enroll-external-officer` | CLI-only (mTLS-bound) |
| Cluster | none — go-qrdb `AdminService` | `cluster` | Dashboard card (clustered / standalone) |
| WebAuthn login/enroll | `/api/v1/webauthn/*` | `user register/login` (USB) | Login (browser passkey) |
| Auth session | `/api/v1/auth/*` | `auth login` | Login / topbar logout |

## Documented CLI-only (local / offline operations)

These act on the machine running the CLI, not the server, so they have no
console equivalent:

- `fido2 *` — USB CTAP2 device operations (console uses browser WebAuthn).
- `pkcs11 *` — local PKCS#11 module probing and slot management.
- `migrate *` — local backend-to-backend key migration.
- `bootstrap noise|dane|spki|direct` — offline trust math / local files.
- `init claim-share` — officer ceremony bound to a local mTLS client cert.
- `init officer register` / `enroll-external-officer` — Security Officer
  enrolment binds an operator-held client certificate, so it runs on the same
  mTLS path as the rest of the ceremony plane rather than through the SDK
  transport client. `init officer status` is readable but stays with it.
- `credential *` — the credential plane rides the same mTLS ceremony path.
  Listing reports names only; rotation is `credential submit` on an existing
  name, so there is no separate rotate verb.
- `ca tcg *` — device EK/AK provisioning and enrollment.
- `key export-material` on hardware — raw material export (CLI convenience).

## Deliberately absent everywhere: an SSH console

xkmsd terminates no SSH session, on any transport. It stores SSH keys and signs
authentication challenges with them (`POST /xkms/v1/ssh/keys/{scope}/{owner}/{name}/sign`);
the session belongs to the client. A console served here would let any
authenticated caller make the appliance dial an arbitrary host and proxy an
interactive shell through it. Use the **xkey** client with this server added as
a backend: the terminal runs on the operator's machine and the private key never
leaves the vault.

## The audit plane is read-only everywhere

`GET /api/v1/audit` (and the Audit screen) read the
tamper-evident, HMAC-chained log owned by the embedded qrdb node. There is no
write endpoint on any transport, by design: the server appends a record as a
side effect of the operation being audited, never on a caller's request, so a
client cannot forge or backdate an entry.

Reading carries its own `audit:read` permission rather than riding on
`keys:*` or `users:*` — the log records who did what to the rest of the API,
so access to it is a separate decision. Paging is by opaque cursor, not
offset: the chain is append-only, so an offset shifts under a reader between
pages. Each event carries `prev_hash`, the chain link that makes the log
verifiable; the CLI's JSON output and the web detail drawer both surface it.

## FROST signing rounds stay on the CLI

The FROST screen manages threshold keys (generate, list, delete) and verifies
finished signatures. The three signing rounds — commit, sign, aggregate — are
coordinated across separate participants who each hold one share, so they run
through `xkmsctl frost`, not a single operator's browser session. Dealer-mode
generation returns one package per participant containing that participant's
secret share; the console masks those until explicitly revealed and discards
them on reload.

## Cluster and auth factors belong to go-qrdb

Cluster status, membership and per-user auth factors are go-qrdb's
`AdminService` and `UserAuthFactorService`, registered on xkmsd's gRPC server
and Unix socket. xkms does not re-host them over REST, so the console has no
page for them: use `xkmsctl cluster` and `xkmsctl auth factor`.
