# Bootstrap Authentication

The IAM half of bootstrap — the trust root, the first operator certificate,
and every admin account created afterwards — is **cert-based**. There is no
setup token, no invitation, and no self-service `/init` registration endpoint.
The first operator identity is a certificate the xkms CA issues during the
`xkmsd init` ceremony; subsequent admins are enrolled by binding an mTLS
certificate (or a FIDO2 credential) to a user record that lives on the
embedded qrdb node.

Identity storage is qrdb's. xkms defines no user, role, or tenant type of its
own; `xkmsctl` creates users and cert bindings through the SDK, which lands on
qrdb's user client (`XKMSService.BindUserCert` →
`users.AddCertBinding`, `pkg/xkms/servicer_user.go:162`). The one cert-binding
identifier in the stack is qrdb's SPKI thumbprint
(`qrdbsdk.ComputeSPKIThumbprint`), computed by `cmd/xkmsctl/admin.go:193`.

What xkms owns is the hardware and PKI side: the `TrustedCA` that signs the
certificates, the Shamir/SO-PIN ceremony that protects the barrier root key,
and the FIDO2/WebAuthn relying party.

## Layering

```
                  +-------------------------------------+
                  | xkms                                |
                  | - pkg/ca TrustedCA (signs certs)    |
                  | - pkg/init CeremonyService          |
                  |   (+ CAAdapter -> qrdb CeremonyCA)  |
                  | - pkg/server/credentials Service    |
                  | - pkg/webauthn RP (FIDO2)           |
                  +------------------+------------------+
                                     |
                                     v
                  +-------------------------------------+
                  | go-qrdb (via sdk/go only)           |
                  | - ceremony state machine + Shamir   |
                  | - users, roles, cert bindings       |
                  | - barrier / seal                    |
                  +-------------------------------------+
```

`pkg/init` (Go package `initialize`, directory named `init` to dodge the
keyword) is a thin adapter over qrdb's ceremony: `initialize.CeremonyService`
wraps `qrdbsdk.CeremonyService`, and `initialize.CAAdapter`
(`pkg/init/ca_adapter.go:36`) bridges xkms's `ca.TrustedCA` to qrdb's
`qrdbsdk.CeremonyCA` seam — a compile-time assertion pins the contract:

```go
var _ qrdbsdk.CeremonyCA = (*CAAdapter)(nil)
```

The adapter forwards `SignCSR`, `IssueCertificate`, `CACertificate`, and
`CABundle` to the xkms CA, and stamps a system-tenant SPIFFE SAN on the SO /
bootstrap certificate when a trust domain is configured, so the control plane
has an identity before any tenant barrier unseals.

## Server Startup Sequence

Subsystems come up in this order in `server.New` (`pkg/server/server.go:322`,
sequence begins at line 352). There is no separate bootstrap step: the
ceremony service is injected by the composing binary via
`Server.SetCeremonyService` (`pkg/server/server.go:1496`) and surfaced to the
transports through `initialize.NewCeremonyAdapter`
(`pkg/server/server.go:547`).

```
 1. QRDB storage      (embedded node: identity plane + KV)
 2. Backends          (software, PKCS#11, TPM2, cloud KMS, ...)
 3. KeyStore
 4. Authentication    (mTLS, JWT, OIDC, composite)
 5. WebAuthn service  (FIDO2 relying party)
 6. Authorization     (auth.Authorizer -> qrdb RBAC)
 7. AuditLogger
 8. Barrier           (AES-256-GCM at-rest encryption)
 9. BarrierRegistry   (per-tenant barrier isolation)
10. PIN Manager       (SO PIN + User PIN)
11. PasswordStore
12. PlatformStore     (sealed credential store)
13. CredentialService
14. PolicyManager     (PCR policy management)
15. Health
16. CA
17. FactorRegistry    (PIV / FIDO2 / PKCS#11 factors)
```

## Ceremony State Machine

The ceremony states are qrdb's, re-exported by `pkg/init/ceremony.go:48`:

```
              xkmsd init (single admin)
 awaiting_init ------------------------------------> operational
       |
       | xkmsd init --barrier-strategy shamir
       |            --shares N --threshold M --so ...
       v
   enrolling  --- claim-cert + claim-share x N --->  operational
```

| Constant | Value | Description |
|----------|-------|-------------|
| `initialize.StateAwaitingInit` | `awaiting_init` | Barrier not initialized; no CA, no admin identity |
| `initialize.StateEnrolling` | `enrolling` | M-of-N: officers still claiming certificates and Shamir shares |
| `initialize.StateOperational` | `operational` | Ready for service |

## Fresh Install Flow

### Single Admin

```bash
xkmsd init --config /etc/xkms/xkmsd.yaml \
  --so-pin <PIN> --user-pin <PIN> \
  --hostname xkms.example.com
```

`runInit` (`cmd/xkmsd/init.go:247`) validates the flags, builds the barrier
and the credential service, then `executeCeremony`
(`cmd/xkmsd/init_ceremony.go:112`) constructs a software-backed `TrustedCA`
and calls `CeremonyService.Initialize(ctx, caInstance)`. On success it writes:

| Artifact | Destination | Notes |
|----------|-------------|-------|
| CA bundle | `<data-dir>/ca-bundle.pem` | Public; the trust root clients pin against |
| SPKI pin | `<data-dir>/spki-pin.txt` | Hex-encoded SHA-256 over the CA SubjectPublicKeyInfo |

The SO identity is CSR-based; the server never holds officer private keys,
so no credential bundle is emitted. State goes straight to `operational`.

### M-of-N (Threshold)

Each Security Officer generates a keypair and CSR offline. The operator passes
one `--so username:/path/to/csr.pem` per officer:

```bash
xkmsd init --config /etc/xkms/xkmsd.yaml \
  --so-pin <PIN> --user-pin <PIN> \
  --barrier-strategy shamir --shares 3 --threshold 2 \
  --so admin1@example.com:/path/to/admin1.csr \
  --so admin2@example.com:/path/to/admin2.csr \
  --so admin3@example.com:/path/to/admin3.csr
```

`--shares` and `--threshold` are only accepted with
`--barrier-strategy=shamir`; passing them with any other strategy is rejected
with `ErrSharesRequiresShamir` (`cmd/xkmsd/init.go:526`).

Init signs each CSR against the new CA, Shamir-splits the barrier root key,
seals the shares, and leaves the ceremony in `enrolling` — each officer
claims their own certificate and share over the network.

Claiming is a challenge-response: `BeginClaimCert` returns a random nonce
(5-minute expiry) that the officer signs with the private key matching the CSR
they submitted; `CompleteClaimCert` verifies that signature before releasing
the certificate. `ClaimShare` then hands over the sealed Shamir share and
deletes it from sealed storage. When every certificate and share has been
claimed, the ceremony transitions to `operational`.

This M-of-N officer ceremony is the **only** multi-party admin path. There is
no "threshold registration" flow where extra admins redeem invitations.

## Admin Enrollment After First Boot

Once the server is operational, admins are added with `xkmsctl admin`
(`cmd/xkmsctl/admin.go`). Enrollment method is selected with `--method`;
`adminCreateHandlers` dispatches to exactly two handlers, `fido2` (default)
and `mtls`.

```bash
# mTLS from a PEM certificate
xkmsctl admin create alice@example.com \
  --method mtls --cert-file /path/to/alice.pem

# mTLS from a PKCS#11 token (module/slot/PIN are root persistent flags)
xkmsctl admin create alice@example.com \
  --method mtls --pkcs11-module /usr/lib/libxkey11.so

# FIDO2 security key (default method)
xkmsctl admin create alice@example.com --display-name "Alice"
```

The mTLS path reads the certificate, computes
`qrdbsdk.ComputeSPKIThumbprint(cert)`, creates the user with role `admin`
(`RoleAdmin`, `cmd/xkmsctl/roles.go:26`), and binds the thumbprint via
`BindUserCert`. Because the identifier is over the SubjectPublicKeyInfo, a
re-issued certificate for the same key resolves to the same binding.

Certificates for new operators come from the CA itself: `POST
/api/v1/ca/sign-csr` (CSR-sign) or `POST /api/v1/ca/issue`
(generate-and-distribute), both authenticated (`pkg/api/rest/server.go:714`).
During the ceremony the SO-authorized equivalent is `init.signCSR`. Neither
path issues a bearer token.

Remaining subcommands:

| Command | Purpose |
|---------|---------|
| `xkmsctl admin list` | List accounts with role `admin` |
| `xkmsctl admin get <username>` | Show one account |
| `xkmsctl admin enable <username>` | Enable an account |
| `xkmsctl admin disable <username>` | Disable an account |
| `xkmsctl admin delete <username>` | Delete an account |
| `xkmsctl admin status` | Report whether any admin accounts exist |

## FIDO2 Integration

`--method fido2` drives the server-side WebAuthn ceremony through the SDK
(`webAuthnRegistration`, `cmd/xkmsctl/user.go:39`):

1. `CreateUser` creates the account on the embedded qrdb node with `RoleAdmin`.
2. `BeginRegistration` returns the server's
   `PublicKeyCredentialCreationOptions` as JSON.
3. `pkg/fido2` performs MakeCredential against the hardware authenticator.
4. The attestation is returned to `pkg/webauthn`'s relying-party service,
   which persists the credential on the qrdb node.

Both halves of the ceremony are wired end-to-end: authentication resolves the
user from the same qrdb-backed credential store, and is integration-tested
against xkey's virtual authenticator
(`test/integration/fido2/{registration,authentication}_ceremony_test.go`),
with a YubiKey-gated hardware path enabled by `XKMS_FIDO2_HARDWARE=1`.

## Secure-by-Default Gate

`Config.ComplianceGaps()` (`pkg/config/config.go:1214`) reports posture gaps
that FedRAMP / PCI-DSS v4 / HIPAA do not permit, and `cmd/xkmsd/main.go:134`
refuses to start when any are present unless the operator passes `--insecure`
or sets `XKMS_INSECURE=true`. The same gate is re-applied on config reload
(`main.go:266`), so a hot reload cannot downgrade a running server.

Gaps relevant to first boot:

| Gap | Trigger |
|-----|---------|
| No CA configured | `ca` is unset — no trust anchor, so no certificate-based admin enrollment is possible |
| Encryption-at-rest disabled | `barrier.enabled=false` |
| Barrier cannot auto-unseal | `barrier.strategy` is passphrase/software/none with no passphrase and no hardware backend — the embedded data plane, including backend key stores, would be plaintext |
| TLS disabled | `tls.enabled=false` |
| Authentication disabled or no-op | `auth.enabled=false`, or `auth.type` resolves to `noop`/`none`/`""` |
| RBAC without an identity plane | `auth.enable_rbac=true` with `storage.backend != "qrdb"` — the authorizer cannot be built and every transport allows everything |

This is why `xkmsd init` is a prerequisite rather than a convenience: a
compliant configuration needs a CA and an encrypted barrier before the daemon
will accept its first connection.

## API Surface

The init ceremony endpoints exist to let an officer collect the artifacts
minted for them during `xkmsd init`. Possession of the CSR private key is the
credential proven by the challenge-response.

Note that on REST these routes sit inside the `/api/v1` group behind
`AuthenticationMiddleware` (`pkg/api/rest/middleware.go`), which carves out
exactly one exemption: the four claim endpoints below are served without an
identity assertion while the ceremony is still in progress, because an
officer's first credential is the certificate those routes hand out
(`pkg/api/rest/middleware_init_public.go`). The exemption fails closed on
five axes:

1. An init ceremony service must be wired on the server; without one no
   request is ever treated as public.
2. The request path must exactly match the four-entry allowlist — prefix
   matching is deliberately avoided so a path like `/api/v1/initialize` can
   never be exempted.
3. A percent-encoded path whose escaped form differs from its decoded form is
   never treated as public, so the string this check inspects can never
   diverge from the string chi routes on.
4. The ceremony state must be on the explicit pre-operational allowlist
   (`awaiting_init`, `enrolling`). Any other state — operational included,
   and any state string a future go-qrdb release might add — restores full
   authentication.
5. `sign-csr` is not in the allowlist at all: it requires the SO PIN and an
   already-enrolled operator, so it stays behind authentication (and RBAC,
   when enabled).

The exemption does not widen the set of parties that can reach the daemon:
possession of the CSR private key is the credential proven by the claim
challenge-response, and the transport is additionally SPKI-pinned against the
pin published by the initialization ceremony. Once the ceremony reaches the
operational state these paths are ordinary authenticated routes.

REST (`pkg/api/rest/server.go:830`):

| Method | Path |
|--------|------|
| GET | `/api/v1/init/status` |
| POST | `/api/v1/init/claim-cert/begin` |
| POST | `/api/v1/init/claim-cert/complete` |
| POST | `/api/v1/init/claim-share` |

QUIC is HTTP/3 served on the same unified REST listener (there is no
separate QUIC server package), so it automatically mounts the same four
routes plus the permission-gated `/api/v1/init/sign-csr`
(`pkg/api/rest/routes.go:312`). MCP exposes them as `xkms_init_*` tools
backing the same JSON-RPC methods, `init.getStatus`, `init.claimCertBegin`,
`init.claimCertComplete`, `init.claimShare`, `init.signCSR`
(`pkg/api/mcp/server.go:509`). gRPC does **not** implement the ceremony —
its transport returns `ErrNotSupported`
(`pkg/api/transport/grpc/transport.go:2247`).

Request/response shapes are the canonical types in
`pkg/api/transport/types_init.go`:

```json
// POST /api/v1/init/claim-cert/begin
{"username": "admin2@example.com"}
// -> {"nonce": "<hex>", "username": "...", "expires_at": "..."}

// POST /api/v1/init/claim-cert/complete
{"username": "admin2@example.com", "nonce": "<hex>", "signature": "<base64>"}
// -> {"cert_pem": "...", "ca_cert_pem": "..."}

// POST /api/v1/init/claim-share
{"username": "admin2@example.com"}
// -> {"share": { ... }}
```

Error mapping (`pkg/api/rest/handlers_init.go:98`):

| Error | HTTP Status |
|-------|-------------|
| `initialize.ErrNotInEnrollingState` | 409 Conflict |
| `initialize.ErrAlreadyInitialized` | 409 Conflict |
| `initialize.ErrCertAlreadyClaimed` | 409 Conflict |
| `initialize.ErrShareAlreadyClaimed` | 409 Conflict |
| `initialize.ErrPendingCertNotFound` | 404 Not Found |
| `initialize.ErrShareNotFound` | 404 Not Found |
| `initialize.ErrUserNotFound` | 404 Not Found |
| `initialize.ErrChallengeNotFound` | 404 Not Found |
| `initialize.ErrChallengeExpired` | 410 Gone |
| `initialize.ErrChallengeVerificationFailed` | 401 Unauthorized |
| anything else | 500 Internal Server Error |

Credential submission (used to hand the daemon a User PIN at start-up under
the `manual` strategy) lives alongside it at `/api/v1/credentials/submit` and
`/api/v1/credentials/strategy` (`pkg/api/rest/server.go:840`).

### Known CLI drift

`xkmsctl init` speaks plain HTTP to the REST endpoint in `--server`, and three
of its subcommands do not currently match the server contract:

- `claim-share` posts to `/api/v1/init/claim-share/begin` and `/complete`
  (`cmd/xkmsctl/init.go:429`, `:474`); the server exposes a single
  `/api/v1/init/claim-share`.
- `claim-cert` generates a fresh keypair and signs the nonce with it
  (`cmd/xkmsctl/init.go:343`), but the server verifies the signature against
  the public key in the officer's CSR, and it reads `cert_pem`, not the
  `certificate` field the CLI decodes.
- `sign-csr` posts to `/api/v1/init/sign-csr`, which is permission-gated (not
  in the anonymous ceremony allowlist), so it is reachable over REST/QUIC and
  MCP but requires an authenticated, authorized caller.

Drive the documented endpoints directly until the CLI is reconciled with the
server contract.

## Barrier Coordination

The barrier comes up at step 8, before the CA at step 16, which means:

- The barrier root key exists before any identity or credential is written.
- Admin records and sealed credentials are stored through barrier-encrypted
  storage.
- In M-of-N mode the barrier root key *is* the secret that was Shamir-split:
  the ceremony seals one share per officer, `ClaimShare` releases and deletes
  it, and the officers' shares are what later reconstruct the root key at
  unseal time (`xkmsctl barrier unseal-shares --share <s> ...`).
- The ceremony and the barrier are separate gates. A server whose ceremony is
  `operational` still refuses key operations while its barrier is sealed.

## Configuration

Bootstrap is driven by `xkmsd init` flags, not by a config block. Each flag
has a Viper-bound `XKMS_*` fallback (`cmd/xkmsd/init.go:464`):

| Flag | Env | Default | Purpose |
|------|-----|---------|---------|
| `--config` | — | `/etc/xkms/xkmsd.yaml` | Configuration file |
| `--so-pin` | `XKMS_SO_PIN` | — | Security Officer PIN (required) |
| `--user-pin` | `XKMS_USER_PIN` | — | User PIN (required) |
| `--barrier-strategy` | `XKMS_BARRIER_STRATEGY` | `passphrase` | `passphrase`, `shamir`, `pkcs11`, `tpm2`, `awskms`, `gcpkms`, `azurekv`, `vault` |
| `--shares` | `XKMS_SHARES` | `0` | Total Shamir shares (only with `--barrier-strategy=shamir`) |
| `--threshold` | `XKMS_THRESHOLD` | `0` | M-of-N threshold |
| `--so` | — | — | `username:/path/to/csr.pem`, repeatable |
| `--credential-strategy` | — | `barrier` | Credential seal strategy |
| `--data-dir` | — | `/var/lib/xkms` | Where public artifacts are written |
| `--hostname` | `XKMS_HOSTNAME` | `localhost` | CN for the admin/server certificate |
| `--sans` | `XKMS_SANS` | — | Additional DNS / IP SANs. Parsed and env-resolved, but not yet consumed by the ceremony (`cmd/xkmsd/init.go:445`) |

`validateInitFlags` (`cmd/xkmsd/init.go:507`) enforces the combinations:
`--shares`/`--threshold` are rejected unless the strategy is `shamir`; with
`shamir`, `--shares >= 2` and `2 <= --threshold <= --shares`; and
`--threshold` may not exceed the number of `--so` officers.

The credential seal strategy is validated against `validStrategies`
(`pkg/server/credentials/service.go:43`): `manual`, `barrier`, `tpm2`,
`pkcs11`, `awskms`, `gcpkms`, `azurekv`, `vault`, `passphrase`, plus the
underscored aliases `aws_kms`/`gcp_kms`/`azure_kv` and `software` for
`passphrase`.

## Service API

`initialize.CeremonyService` (`pkg/init/ceremony.go:88`):

| Method | Description |
|--------|-------------|
| `NewCeremonyService(config, barrier, credService, logger)` | Validates the config and wraps qrdb's ceremony service |
| `Initialize(ctx, ca.TrustedCA)` | Runs the ceremony; returns `InitResult` (state, SPKI pin, CA bundle, share count) |
| `BeginClaimCert(ctx, username)` | Issues a 5-minute challenge nonce |
| `CompleteClaimCert(ctx, username, nonceHex, signature)` | Verifies possession, returns cert + CA cert |
| `ClaimShare(ctx, username)` | Returns and destroys the officer's sealed Shamir share |
| `SignCSRInit(ctx, username, soPin, csrPEM, role)` | SO-authorized CSR signing during init |
| `State()` | Current ceremony state (concurrency-safe) |
| `SPKIPin()` | Hex-encoded SPKI pin of the CA |
| `SetSPIFFETrustDomain(td)` | Enables system-tenant SPIFFE SAN stamping |
| `ThresholdRegistry()` | Registry for vendor HSM threshold initializers |
| `Cleanup()` | Destroys remaining shares and clears sensitive state |

The running server reaches the ceremony through `XKMSService`, which stores it
as `any` (`pkg/xkms/service.go:128`) to break the
`xkms -> init -> ca -> xkms` import cycle; `SetCeremonyService` /
`CeremonyService()` are the accessors and the transport layer type-asserts to
`transport.InitCeremonyService`.

## Removed Design: Setup Tokens

An earlier design bootstrapped the first admin with a one-time setup token
plus `POST /api/v1/init`, and added extra admins with invitation tokens via
`POST /api/v1/init/threshold`. **That design was removed.** No setup-token,
invitation, or `/api/v1/init` (bare) route exists in `pkg/`, `cmd/`, or
`sdk/`, and admin enrollment is now cert-based by architectural rule:
CSR-sign or generate-and-distribute, never an invite token. Stale references
in `docs/ROADMAP-bootstrap.md` describe this removed design.

## Cross-References

- [Init System](../init/README.md) — the KMS + CA half of `xkmsd init`
- [Identity / authorization layering](layering.md) — the qrdb boundary and the `auth.Authorizer` seam
- [RBAC](../architecture/rbac.md) — permission vocabulary and per-transport gates
- [Barrier Architecture](../seal/README.md) — at-rest encryption design
- [WebAuthn RP](../webauthn/README.md) — the relying party behind `--method fido2`
- [Trust Bootstrap Library](../trust/bootstrap.md) — the client-side library that fetches the CA bundle produced here
- [Bootstrap CA Configuration](../configuration/bootstrap.md) — CA bundle bootstrap (separate from init)
