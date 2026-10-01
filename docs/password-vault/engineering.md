# Password Vault — Engineering Contract

> **Status: NORMATIVE** · Feature: `password-vault` · Repo: `go-xkms` · Last verified: 2026-10-01

## Exported surface — `pkg/staticpw`

### Access control (`access.go`)

```go
type AccessMode string

const (
	// AccessPINPerOperation requires a PIN for every decryption operation.
	AccessPINPerOperation AccessMode = "pin_per_operation"
	// AccessSessionBased requires a single PIN unlock, then allows free
	// access until the store is locked again.
	AccessSessionBased AccessMode = "session_based"
)
```

`access.go` defines only this type and the two constants -- no store
implementation lives here. `AccessSessionBased` is implemented by
`TenantPasswordStoreManager`: a user's session is the user's DEK, unwrapped by
one of the user's vault factors and held until the user locks or the tenant
barrier seals. There is no store implementation of `AccessPINPerOperation`:
`XKMSService.PasswordStoreSetAccessMode` only succeeds when the requested mode
already equals the store's active mode, and the active mode for a tenant
store is always `AccessSessionBased`.

### The personal vault (`vault.go`, `dek_backend.go`)

```go
type FactorType string // FactorPassphrase, FactorPasskey, FactorRecovery,
                        // FactorPIV, FactorCertificate, FactorTPM (IsKeyFactor)

type VaultCredential struct {
	Type         FactorType
	Secret       *secure.Secret // passphrase, hmac-secret output, or recovery code
	CredentialID []byte         // passkey
	PRFSalt      []byte         // passkey enrollment: the 32-byte hmac-secret salt
	Label        string
}

// TenantPasswordStoreManager
VaultStatus(ctx, tenant, subject) (*VaultStatus, error)
EnrollFactor(ctx, tenant, subject, cred) (*EnrollResult, error) // first: mints DEK + recovery code
UnlockUser(ctx, tenant, subject, cred) error                   // passphrase or passkey
RotateFactor(ctx, tenant, subject, factorID, cred) (*EnrollResult, error)
RemoveFactor(ctx, tenant, subject, factorID) error
RecoverVault(ctx, tenant, subject, recoveryCode, cred) (*EnrollResult, error)
LockUser(tenant, subject) error
```

Constants: `MinPassphraseLength` 8 (NIST SP 800-63B), `PasskeySecretLength`
32, `PRFSaltLength` 32. Passphrase KEK: Argon2id at `kdf.DefaultParams`
(64 MiB, t=3, p=4) by default, the cost recorded on each factor so changing
it only affects new wraps. `NewTenantPasswordStoreManager` takes functional
`Option`s; `WithPassphraseKDFParams(func() *kdf.KDFParams)` overrides the
default. Production callers never need it. Tests across every package that
builds a manager do: `pkg/testutil/kdftest.CheapPassphraseParams` is a cost
cheap enough that enrolling and unlocking a passphrase factor many times, in
parallel, does not dominate a suite's runtime or memory while still
exercising the production wrap/unwrap path. `kdftest` imports only
`pkg/crypto/kdf`, not `pkg/staticpw`, so that a fixture package the
transports' tests use (`pkg/testutil/vaulttest`) does not pull `staticpw`'s
dependency chain back into a transport's own test package and form an
import cycle. Passkey and recovery KEKs: HKDF-SHA256 with a per-factor salt
and a domain-separated info string.
Every wrap and every personal entry is AES-256-GCM with associated data
binding it to its tenant, user and factor (wraps) or storage key (entries).

`VaultCredential.Secret` is sealed in protected memory
(`sdk/go/secure.Secret`), never a plain `[]byte` or `string` struct field. It
is opened only for the duration of a key-encryption-key derivation
(`vaultFactor.kek`) or a length check (`VaultCredential.validate`), and the
opened `*secure.Buffer` is destroyed immediately after. The servicer layer
(`pkg/xkms`'s `vaultCredential`) is the boundary: it seals a transport
request's plaintext secret into a `*secure.Secret` and the caller destroys it
after the vault call returns. Wire and transport types
(`transport.PasswordVaultCredential`, and the REST/gRPC/MCP request types)
carry the secret as plaintext bytes up to that boundary.

Key factors (`vault.go`, `pkg/vaultkey`, `pkg/vaulttoken`): `wrap` seals a
fresh secret to the factor's public key (`vaultkey.Seal`) and keeps only
`KeyAlgorithm`, `KeyChallenge`, `KeyCheck` and `KeyFingerprint`; `kek`
derives the KEK with `HKDF-SHA256(secret, salt, "xkms/staticpw/vault/v1/key|"
+ fingerprint)`; `unwrapWith` matches a key-factor credential by type and
fingerprint. `VaultKeyError` (matches `ErrVaultInvalidCredential`) reports a
key that does not parse or is unsupported; `ErrVaultKeyExists` a key already
enrolled. Client side, `vaulttoken.Resolve` finds the key in an xkms backend
(PIV: the backend's slot 9d key, `xkms.PivSlotCN("9d")`), `SelfTest` proves
the token can open a secret sealed to it, `EnrollCredential` builds the
enrollment, and `Find`/`UnlockCredential` recover a vault factor's secret.
The TPM 2.0 backend's `Decrypter` decrypts RSA-OAEP-SHA-256 through
`TPM2.RSADecrypt`, authorized by the key's own policy session.

Passkey relying party: `WithPasskeyRelyingParty(rpID)` on
`NewTenantPasswordStoreManager` (compose `Deps.PasskeyRelyingParty`, xkmsd's
`webauthn.rp_id`, the module's `WithPasswordVaultRelyingParty`); without it
passkey enrollment answers `ErrVaultPasskeyUnavailable`, and a passkey for
another relying party `ErrVaultRelyingPartyMismatch`.

Personal names (`names.go`): a personal store's `entryNames` is keyed with
`HKDF-SHA256(DEK, "xkms/staticpw/personal/v1/names")`, so its entry IDs and
folder-marker and alias key segments are 128-bit HMAC-SHA-256 values (32 hex
characters) instead of `GenerateID`'s public hash and the plain text; an
opaque folder marker stores its path in its sealed value. The key is zeroed
with the DEK when the session ends. The zero `entryNames` is the public
scheme of shared, system and xkey-local stores, unchanged.

Invariants: the DEK never changes (so personal entry IDs are stable across
sessions); a vault always has a recovery factor
(written before the first factor); a user's vault changes are serialized per
user, so racing first enrollments mint one DEK; rotation writes the new wrap
before removing the old one; recovery writes the new factor and the new code
before retiring the used code.

Errors: `ErrVaultNotInitialized`, `ErrVaultCredentialRejected` (a wrong
secret, unknown passkey or wrong code -- never says which),
`ErrVaultInvalidCredential`, `ErrVaultFactorNotFound`, `ErrVaultLastFactor`,
`ErrVaultRecoveryFactor`, `ErrVaultPasskeyExists`, `*VaultStoreError`,
`*VaultCryptoError`, `*PersonalEntryDecryptError`.

Service layer (`pkg/xkms/servicer_password_vault.go`): `PasswordVaultStatus`,
`PasswordVaultEnroll`, `PasswordVaultRotate`, `PasswordVaultRemoveFactor`,
`PasswordVaultRecover`, and `PasswordStoreUnlock` with a
`transport.PasswordVaultCredential`. Each acts on the caller's own vault; a
request without an identity gets `ErrOperationNotSupported`.

### Scoping (`scope.go`, `scoped_store.go`)

```go
type PasswordScope string          // scope.go:17
```

Scoped and tenant-scoped stores compose over the base store:
`scoped_store.go`, `tenant_store_manager.go`. The team store
(`team_entity.go`, `team_store.go`) only records teams and their members for
xkey's local GUI; no password is shared through it.

### Stores

`store.go`: `BackendStore` (`store.go:107`), wrapping a `storage.Backend` --
at-rest confidentiality is the backend's (the tenant barrier), not a
`staticpw`-owned cipher. `scoped_store.go`: `ScopedStore`, splitting personal
and shared entries over two `BackendStore`s. Both implement `Store`
and share one `Get` contract: return the entry exactly as stored, with no
decrypt- or PIN-aware variant. Entries: `entity.go`, `team_entity.go`,
`types.go`. Support: `generator.go`, `expiry.go`, `validation.go`,
`errors.go`.

### Client contract — `sdk/go/transport`

```go
type PasswordService interface {
	PasswordAdd(ctx, req *PasswordAddRequest) (*PasswordAddResponse, error)
	PasswordGet(ctx, req *PasswordGetRequest) (*PasswordGetResponse, error)
	PasswordList(ctx, req *PasswordListRequest) (*PasswordListResponse, error)
	PasswordUpdate(ctx, req *PasswordUpdateRequest) error
	PasswordDelete(ctx, req *PasswordDeleteRequest) error
	PasswordStoreUnlock(ctx, req *PasswordStoreUnlockRequest) error
	PasswordStoreLock(ctx) error
	PasswordStoreStatus(ctx) (*PasswordStoreStatusResponse, error)
	PasswordStoreSetAccessMode(ctx, req *PasswordStoreSetAccessModeRequest) error
	PasswordGenerate(ctx, req *PasswordGenerateRequest) (*PasswordGenerateResponse, error)
}
```

## Invariants

- **`PasswordGet` returns entries exactly as stored.** There is no per-request
  decryption step and no plaintext/metadata split
  (`pkg/xkms/servicer_password.go:168`); `PasswordList` never returns the
  password field, matching `PasswordGet`.
- **Only `session_based` is reachable, and sessions are per user.** A caller
  must unlock its own personal session before any personal read or write
  succeeds; shared entries need no session, only an unsealed tenant barrier; there is no way to satisfy an operation with a
  per-call PIN instead (`access.go:17`-`26`).
- **A locked store answers status, not secrets.** `PasswordStoreStatus` works
  while locked; that is what makes it useful.
- **Scope is enforced, not advisory.** `own | shared | all` determines what a
  listing returns; a caller cannot widen it by asking.
- **Expiry is metadata.** `expires_at` marks an entry; nothing in this package
  invalidates the credential.
- **Generation has one implementation.** `generator.go`. A second generator at a
  call site is a defect.
- **Encryption is the barrier's.** `BackendStore` delegates to `storage.Backend`
  (`store.go:105`-`117`); `staticpw` does not implement a cipher.
- **Concurrency.** Stores are safe for concurrent use. Session state in
  `TenantPasswordStoreManager` is a lock-free `sync.Map` of open sessions per
  tenant, keyed by subject: `UnlockUser`/`LockUser` touch only the caller's
  entry, so one user's session never opens or closes another's. Sealing the
  tenant barrier clears every session of that tenant.
- **Manager API.** `ResolveScopedStore(tenant, subject)` (shared entries,
  plus personal ones while the session is open; `""` tenant is the unscoped
  system store for identity-less requests), `UnlockUser`, `LockUser`,
  `IsUserLocked`, `UserStoreStatus`. The system tenant (`"system"`) is served
  over the registry's system barrier. The transports never call the manager:
  they call the `XKMSService` password servicer, which resolves the caller
  with `scope.TenantName(identity.TenantID)` and `identity.Subject`.

## Error semantics

`pkg/staticpw/errors.go`. The distinctions that matter:

| Condition | Meaning |
|---|---|
| store locked | a personal operation without the caller's session open |
| vault not initialized | unlock or factor management before any enrollment |
| invalid credential | a malformed credential (short passphrase, wrong-length hmac-secret output or salt, unknown factor) |
| credential rejected | the credential unwraps no factor (wrong passphrase, unknown passkey, wrong output or code) |
| entry not found | wrong ID, or out of the caller's scope |
| validation failure | malformed entry — `validation.go` |

**Fail closed:** a locked session, a missing, malformed or wrong credential,
and an out-of-scope entry all refuse. An out-of-scope entry reports as not-found
rather than forbidden, so entry existence is not enumerable across scopes.

## Configuration

`PasswordStoreSetAccessMode` (`xkmsctl password access-mode <mode>`) validates
against the store's already-active mode rather than switching it; see
"Access control" above. A deployment's access mode is fixed by which store is
wired at startup, not by this call.

Per-entry: name, username, URL, notes, folder, `expires_at` (RFC 3339),
`tenant_id`, `shared`.

Per-listing: `folder`, `tenant_id`, `scope` (`own | shared | all`).

Generation: `length` (`0` = server default).

xkey's daemon takes `--password-store` (default `./data/staticpw`) for the
desktop-local store.

## Persistence

Through `BackendStore` to a `storage.Backend` that is the tenant barrier for
encryption at rest, under the `pkg/scope` keyspace. Tenant and user scoping is
`tenant_store_manager.go` + `scoped_store.go`.

There is no dedicated migration file in this package; entry-layout changes
go through the same `Store`/DAO surface as any other change (no-backward-compat:
pre-release, so old layouts are not carried forward).

## Test strategy

- **Unit** — one suite per file in `pkg/staticpw`, with `access`, `scope`,
  `team_*`, `expiry`, `generator` and `validation` each covered independently.
  `personal_names_test.go` scans the raw tenant barrier and proves no
  personal storage key or value contains an entry name, folder, alias or
  public `GenerateID` of them, that IDs are keyed per user and stable across
  sessions, and that lookups, folders, aliases, moves and renames still work.
- **Key factors** — `vault_keyfactor_test.go` (every key factor type, EC and
  RSA: enroll, unlock, wrong token, forged secret, duplicate key, rotate,
  remove, recover, and a barrier scan proving the server holds no secret);
  `pkg/vaultkey` (seal/open on the software backend for P-256/384/521 and
  RSA, wrong key, unsupported keys); `pkg/vaulttoken` (every factor through
  a real vault service, wrong and missing tokens, self-test), with
  `vaulttoken_tpm_sim_test.go` (`-tags tpm_simulator`: TPM2_ECDH_ZGen and
  TPM2_RSA_Decrypt under the platform policy) and
  `vaulttoken_pkcs11_test.go` (`-tags pkcs11`, SoftHSM: PIV slot 9d and
  certificate keys, a token without RSA-OAEP-256 caught by the self-test,
  another token refused). xkmsctl's `password_vault_key_tpm_sim_test.go`
  enrolls and unlocks a TPM key under `platform` and under a named policy
  created in the data directory's registry (refused once the PCR drifts).
  `make test` runs them all: `tpm_simulator` is in `TEST_TAGS`, and the
  `test-pkcs11` lane adds `pkcs11` for `./pkg/vaulttoken/...`.
- **SoftHSM 2.6 and RSA-OAEP.** SoftHSM 2.6 implements `CKM_RSA_PKCS_OAEP`
  with SHA-1 only and answers `CKR_ARGUMENTS_BAD` for the SHA-256 OAEP the
  vault seals RSA factors with (RSA-OAEP-256). This is deliberate: the vault
  does not fall back to SHA-1. An RSA key on such a token is refused at
  enrollment by `vaulttoken.SelfTest` (the pkcs11 suite asserts exactly
  that); EC keys (ECDH-ES) work on it. Hardware PIV cards and HSMs with
  SHA-256 OAEP are unaffected.
- **Local TPM policies** -- `pkg/localtpm` is the one implementation of the
  TPM policy service a client runs over its own TPM (registry, policy
  authority, NV indexes, approval counter), built exactly as xkmsd builds
  it. xkey (GUI, `xkey tpm policy`, boot-time auto-unseal) and xkmsctl
  (`--tpm-data-dir`) both open it; `localtpm_sim_test.go` covers a key
  created under a named policy, its recorded assignment and its refusal
  after PCR drift.
- **Passkeys** — `pkg/vaultpasskey` (relying party recorded and required,
  cross-surface secret vectors), `sdk/ts/src/vaultPasskey.test.ts` (WebAuthn
  PRF over a fake authenticator, typed errors, the same vectors), and the
  console's Playwright `e2e/password-vault-passkey.spec.ts` (Chrome's
  WebAuthn stack with a CDP virtual authenticator with PRF).
- **Browser bridge** — xkey `pkg/gui/services/staticpw_vault_bridge*_test.go`
  (origin rules, approval, denial, timeout, user mismatch, and the whole
  chain extension -> encrypted native host -> IPC -> service -> vault),
  `pkg/ipc/server_vault_test.go`, the extension's `npm test`
  (`src/vaultBridge.test.ts`: browser-attributed origin, top frame only,
  validated fingerprints), `sdk/ts/src/vaultBridge.test.ts`, and the
  console's `e2e/password-vault-xkey.spec.ts`.
- **Transport** — `pkg/api/rest/password_handlers_test.go`;
  `pkg/api/mcp/handlers_password_test.go`, `handlers_password_unlock_test.go`;
  `pkg/xkms/servicer_password_test.go`.
- **Cross-module** — xkey's autofill and extension suites exercise the same
  store through IPC.
- **Integration** — `make integration-test-password-vault` (devcontainer, as
  root for `/dev/uhid`) runs `xkey/test/integration/password`, the one
  password suite: xkey's local store CLI and, against a real xkmsd started
  by `test/integration/xkmsdtest` (passphrase barrier initialized through
  the sealed window, REST over mTLS, relying party `localhost`), the real
  xkmsctl and xkey binaries on every vault factor's real token -- enroll,
  unlock, wrong token, missing token:
  - passphrase and certificate key (xkmsctl);
  - passkey on xkey's virtual FIDO2 authenticator (`test/integration/xkeytest`),
    named with `--device`, plus a wrong PIN;
  - TPM key on the swtpm fixture (`--tpm-device tcp://swtpm:2321`) under
    `platform` and under a named policy created with `xkey tpm policy`,
    refused after the PCR drifts and re-approved by `policy update`; each
    test undefines the NV indexes it defined, so the fixture does not fill;
  - PIV slot 9d on a SoftHSM token, provisioned with `xkey piv generate`
    and used through `xkey password vault` (`--pkcs11-token`);
  - the recovery code (recovers once, then refused; a wrong code refused);
  - two ordinary users (the built-in `user` role, which holds
    `passwords:write` and `passwords:delete`): personal entries isolated, the shared entry visible
    to both, and a shared entry its owner made refused to the other user's
    update and delete;
  - the browser bridge: the real native host (`xkey extension host`) with
    the pairing ceremony, encrypted native messaging, the xKey password
    service behind IPC approving the request; a wrong origin is refused
    before the user is asked.

The two cases worth explicit tests in any consumer: a `get` against a locked
store, and a read of an entry outside the caller's scope. Both must fail, and
the second must fail as not-found
(`TestPasswordGet_LockedSessionReturnsErrStoreLocked`,
`pkg/xkms/servicer_password_test.go:1421`).

## Observability

Password reads are auditable events — `subject`, `action`, `resource:
passwords`, `resource_id`, `outcome` — through
[`../audit-log/`](../audit-log/engineering.md). **Entry names and IDs are
loggable; values never are**, and neither are the fields around them that people
put passwords in by mistake (`notes` is free-form and reaches storage).
