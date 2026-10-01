# Password Vault — Architecture

> **Status: NORMATIVE** · Feature: `password-vault` · Repo: `go-xkms` · Last verified: 2026-09-30

## The problem

Not every secret is a key. A trusted-computing stack still has to deal with the
ordinary ones — the login for an upstream service, a database password, the
credential a browser autofills — and those have properties keys do not: they are
human-readable, they get shared within a team, they expire, and someone has to
be able to *see* them.

`pkg/staticpw` is that store, and it lives here rather than in xkey because the
desktop companion is one client of it, not its owner.

## Shape chosen: an entity store with scope, expiry, and two access modes

The core is a set of small, composable stores rather than one type:

| Concern | File |
|---|---|
| Entry model | `types.go` |
| Base store | `store.go` |
| Scoping | `scope.go`, `scoped_store.go` |
| Teams (xkey's local team list only) | `team_entity.go`, `team_store.go` |
| Tenancy | `tenant_store_manager.go` |
| Access control | `access.go` |
| Expiry | `expiry.go` |
| Generation | `generator.go` |
| Validation, errors | `validation.go`, `errors.go` |

`store.go`'s `BackendStore` is the only concrete `Store`. Shared entries are
encrypted at rest by the tenant barrier alone. Personal entries additionally
pass through `dek_backend.go`, which seals every value with the owner's own
data key before it reaches the barrier (see "The personal vault" below).

The design decision that shapes everything else is **access mode**
(`access.go:23`):

```go
type AccessMode string

const (
	AccessPINPerOperation AccessMode = "pin_per_operation"
	AccessSessionBased    AccessMode = "session_based"
)
```

- **`pin_per_operation`** — every read of a plaintext password requires the user
  PIN. Maximum protection, maximum friction.
- **`session_based`** — unlock once, then reads work until the store is locked
  again. What people actually use.

Only `session_based` is a reachable code path today, and a session belongs to
one **user**, not to the tenant: `TenantPasswordStoreManager.UnlockUser` /
`LockUser` open and close one user's personal session, and the session is
opened with one of the user's own vault factors (below), never a
deployment-wide PIN. `pin_per_operation` is a defined
`AccessMode` constant (`access.go`) with no store implementation behind it.
Making the mode an explicit, switchable value rather than a hardcoded policy
is what leaves room for a future per-operation implementation without another
API shape.

### Scope and lock semantics

The vault follows the xkms scope model
([`../multi-tenancy/architecture.md`](../multi-tenancy/architecture.md#ownership-scopes)):

| Entries | Keyspace | Who sees them | When |
|---|---|---|---|
| Shared | `{tenant}/staticpw/shared/` | every authenticated user of the tenant | whenever the tenant barrier is unsealed; no session needed |
| Personal | `{tenant}/staticpw/users/{subject}/` | only their owner | only while the owner's personal session is unlocked |

- **One user locking never locks another.** Sessions are held per
  `(tenant, subject)`. A locked user still reads and writes shared entries;
  personal operations answer `ErrStoreLocked`, and a listing of all entries
  holds the shared ones only.
- **Sealing ends every session.** A tenant barrier that is sealed and later
  unsealed does not resume the sessions it ended.
- **Modifying a shared entry** is restricted to its owner or a member of the
  tenant's Admin/SO built-in role (`checkSharedPasswordOwnership`); any tenant
  user may read it.
- **The system tenant is a tenant.** A system-tenant identity is served from
  `system/staticpw/...` under the system barrier, with its own shared and
  personal entries, and never sees a tenant's entries (nor a tenant the
  system tenant's). Only a request with no identity at all (an internal caller,
  or authentication disabled) is served from the unscoped system store.

Rejected for the lock: a tenant-wide session (the previous design). One user
locking locked everyone, and one user unlocking opened every user's session.

### The personal vault

Personal entries are sealed with a random per-user **data key (DEK)**
(`vault.go`, `dek_backend.go`), so reading them takes one of the user's own
factors: the tenant barrier key alone opens nothing.

```
personal entry ──AES-256-GCM(DEK, aad = storage key)──▶ tenant barrier
storage key    = {tenant}/staticpw/users/{subject}/HMAC(K_names, name)   K_names = HKDF(DEK)
DEK ──wrapped, once per factor──▶ {tenant}/staticpw-vault/users/{subject}/factors/{id}
      passphrase: KEK = Argon2id(passphrase, salt)          64 MiB, t=3, p=4 (kdf.DefaultParams)
      passkey:    KEK = HKDF-SHA256(hmac-secret output, salt) FIDO2 hmac-secret / WebAuthn PRF
      recovery:   KEK = HKDF-SHA256(recovery code, salt)    160-bit code, one-time
      wrap = AES-256-GCM(KEK, DEK, aad = tenant|subject|factor id)
```

- **Enrollment.** A user enrolls a passphrase, a passkey, or both. The first
  enrollment mints the DEK, wraps it under the factor and under a new
  **recovery code**, opens the session and returns the code, which is shown
  exactly once and never stored in the clear. Later enrollments need the
  session open, so nobody else can add a factor to a user's vault.
- **Passkeys.** A passkey factor is a FIDO2 credential with the hmac-secret
  extension (the CTAP2 primitive behind WebAuthn's prf), created for the
  server's WebAuthn relying party (see "The passkey relying party"). Every
  non-browser client uses one implementation, `pkg/vaultpasskey`
  (`sdk/go/vaultpasskey`); the browser uses `sdk/ts` `vaultPasskey.ts`; see
  "Passkey salt handling".
- **Rotation of a passkey** is enrolling a new passkey and removing the old
  one: a passkey's secret is bound to its credential.

### The passkey relying party

A browser creates and evaluates a WebAuthn credential only for its own
origin's domain or a parent of it, and an authenticator answers for a
credential only under the relying party ID it was created for. So the one
relying party every surface can share is the domain the web console is
served from: the server's configured WebAuthn relying party,
`webauthn.rp_id` (`staticpw.WithPasskeyRelyingParty`; a host module passes
it with `WithServiceModulePasswordVaultRelyingParty` or its WebAuthn config).

- The vault status advertises it as `passkey_rp_id`; a client creates every
  new passkey for it, and enrollment refuses another one
  (`ErrVaultRelyingPartyMismatch`).
- Each passkey factor records the ID it was created for (`rp_id`), and every
  client evaluates the passkey for the recorded ID, so changing the
  deployment's relying party later leaves existing passkeys working where
  they can.
- With no relying party configured the deployment offers no passkeys:
  enrollment answers `ErrVaultPasskeyUnavailable` (REST 412) on every
  surface, and clients refuse before touching the key
  (`vaultpasskey.ErrNoRelyingParty`, the browser's
  `VaultPasskeyUnavailableError`).
- Rejected: a fixed, non-domain relying party ID (the first design used
  `xkms-password-vault`). A browser refuses it, so a passkey enrolled from a
  CLI could never open in the console and the reverse.

### Passkey salt handling

The salt is defined exactly as WebAuthn's prf extension defines it, so a
passkey enrolled from a CLI, the xkey GUI or a browser unlocks from all of
them:

| Step | Value |
|---|---|
| PRF salt (stored by the server on the factor, `prf_salt`) | 32 random bytes, chosen by the enrolling client |
| hmac-secret salt the authenticator receives | `SHA-256(UTF8("WebAuthn PRF") ‖ 0x00 ‖ prf_salt)` — `fido2.WebAuthnPRFSalt` |
| factor secret (sent as `secret`) | the 32-byte hmac-secret output: `HMAC-SHA-256(CredRandomWithUV, hmac-secret salt)` |
| KEK | `HKDF-SHA256(secret, factor salt, "xkms/staticpw/vault/v1/passkey")` |

- **Enroll:** MakeCredential with hmac-secret for the advertised
  `passkey_rp_id`, a fresh 32-byte `prf_salt`, one hmac-secret evaluation
  over the transformed salt; send `{factor: "passkey", credential_id,
  prf_salt, secret, label, rp_id}`.
- **Unlock:** read `credential_id` and `prf_salt` from the vault status,
  evaluate hmac-secret over the transformed salt, send `{factor: "passkey",
  credential_id, secret}`. The client tries each passkey factor until one
  is on the authenticator.
- **A browser** creates with `navigator.credentials.create` (rp `rp_id`,
  `userVerification: "required"`, `extensions: {prf: {eval: {first:
  prf_salt}}}`), and evaluates with `navigator.credentials.get` with the
  factor's `rp_id`, `userVerification: "required"` and
  `prf.evalByCredential` (each passkey over its own salt, one ceremony); the
  browser applies the transform itself and `results.first` is the `secret`.
  A browser or authenticator that returns no PRF result is reported as
  `VaultPasskeyPrfUnsupportedError`, with guidance; there is no fallback.
- **User verification is always required.** CTAP2 keys the output with
  `CredRandomWithUV` when the user is verified and `CredRandomWithoutUV` when
  not, so a factor would stop opening if one surface verified and another
  did not. Every vault passkey evaluation is PIN-verified (`vaultpasskey`
  refuses without a PIN); a security key without a PIN must have one set
  first.
- **Proof:** `pkg/fido2/testdata/webauthn_prf_salt_vectors.json` holds the
  transform's vectors and `vault_passkey_secret_vectors.json` the factor
  secret a credential yields for a salt; `pkg/fido2` and `pkg/vaultpasskey`
  (the CLI/GUI path) and `sdk/ts` (WebCrypto, the browser computation) are
  tested against the same files. `pkg/vaultpasskey` proves end to end that a
  passkey enrolled by a client unlocks with a browser-computed prf output
  while an output over the untransformed salt is refused, and the console's
  Playwright suite (`e2e/password-vault-passkey.spec.ts`) runs enroll and
  unlock through Chrome's real WebAuthn stack with a CDP virtual
  authenticator that has PRF.
- **Rotation** re-wraps the DEK under a new secret for a factor of the same
  type and removes the old wrap. **The DEK never changes**, so nothing is
  re-encrypted.
- **Recovery** uses the code to enroll a new factor when the others are
  lost. The code is one-time: recovery replaces it with a new one, shown once.
  It does not unlock on its own.
- **Removal** refuses the recovery factor and the last passphrase or passkey.
- **Lock** zeroes the DEK; sealing the tenant barrier ends every session and
  zeroes every DEK.
- The deployment-wide user PIN (PIN management) no longer gates the password
  store; it remains for the features that use it (the PKCS#11 token, PIN
  management itself).

Rejected: wrapping the DEK under the tenant barrier only. The barrier would
then unwrap it, and the tenant key alone would read every personal entry.
Rejected: a DEK per entry. It adds nothing a per-user key does not give, and
multiplies the wraps a rotation would have to touch.

Rejected alternatives:

- **Storing passwords as keys in the keystore.** Rejected: keys are not
  readable by design, and a password that cannot be read is not a password.
- **Implementing the vault in xkey.** Rejected by the ownership rule — reusable
  logic lands in `go-xkms/pkg/*` and xkey consumes it through
  `go-xkms/sdk/go`. xkey is a shell, never a second implementation.
- **One access policy.** Rejected — see above.

## Component boundaries

| Piece | Where | Owner |
|---|---|---|
| The vault | `pkg/staticpw` | go-xkms |
| Wire surface | `pkg/api/rest/password_handlers.go`, `pkg/api/mcp/handlers_password.go`, `transport.PasswordService` | go-xkms |
| CLI | `cmd/xkmsctl/password.go` | go-xkms |
| Desktop client, autofill, browser extension | `xkey` (`xkey password …`, `xkey/pkg/autofill`, `xkey/extension`) | go-xkms (xkey surface) |
| Encryption at rest | the barrier — [`../sealing-and-barrier/`](../sealing-and-barrier/architecture.md) | **go-qrdb** owns the barrier |
| Tenancy model | go-qrdb | **go-qrdb** |

Capability row: **"Password vault + autofill (core store: `go-xkms/pkg/staticpw`)"**
under the xkey product surface — note that the row itself names this package as
the core.

## Data flow

```
add:     xkmsctl password add NAME --password -
           → validation → entity → scoped/team/tenant store
             → storage.Backend → the barrier

read:    xkmsctl password get ID
           → shared entry: served while the tenant barrier is unsealed
           → personal entry: the caller's own session gate (session_based,
             the only implemented mode — requires the caller's own prior
             `password unlock`)
             → store.Get → entry returned exactly as stored

           `--decrypt`/`--user-pin` on this call always fail with
           ErrPasswordDecryptNotSupported (servicer_password.go:188): there
           is no field-level decrypt step to opt into — a plain `get`
           already returns the entry as stored, because `pkg/staticpw` does
           not encrypt the `Password` field itself.

autofill: browser extension → native-messaging host → xkey IPC → the same store
```

Locking (`password lock`) drops the caller's own session; `password status`
reports whether the caller's session is unlocked, whether the tenant barrier is
sealed, and how many entries the caller can read now.

Every transport (REST, gRPC, MCP) reaches the store only through the
`XKMSService` password servicer, so the scope rule, the ownership check and the
session gate are enforced once.

## Trust boundaries

- **There is no field-level decrypt boundary.** `PasswordGet` refuses
  `--decrypt`/`--user-pin` outright (`ErrPasswordDecryptNotSupported`,
  `pkg/xkms/servicer_password.go:188`): a plain `get` already returns the
  entry exactly as stored, because `pkg/staticpw` never encrypted the
  `Password` field on its own. The real boundaries are the scope (a user's
  personal entries live under that user's own keyspace and no other caller's
  store contains them) and the per-user session lock: personal
  `list`/`get` fail with `ErrStoreLocked` until that user's `password
  unlock` succeeds.
- **Access mode is the policy.** `session_based` — the only implemented mode
  — means anything that can act as a user while that user's session is
  unlocked can read that user's personal entries, and any tenant user can
  read the shared ones. `pin_per_operation` is a defined value with no store
  behind it; it re-authenticates nothing today.
- **Personal entries need the owner's factor.** Their values are sealed with
  the owner's DEK, which exists in the clear only in memory while the owner's
  session is open. A holder of the tenant barrier key reads ciphertext and
  wrapped DEKs, and storage keys that name nothing: a personal entry's ID is
  `HMAC-SHA-256(K_names, "entry" ‖ 0x00 ‖ lower(folder/name))` truncated to
  128 bits, and a personal folder marker's or alias's key segment is the same
  MAC of its text (kinds `folder`, `alias`), with
  `K_names = HKDF-SHA256(DEK, info "xkms/staticpw/personal/v1/names")`. The
  folder path a marker stands for and an alias's target are stored in its
  DEK-sealed value. The MAC is keyed per user, so the same name gives
  different IDs to different users and nobody without the DEK can test a
  guessed name against a key. **Residual:** the barrier key still shows that
  a subject has a vault (the subject is a keyspace segment), how many
  personal objects it holds (entries, folder markers and aliases are counted
  separately by their key prefixes), their sizes, and when they change.
  Shared entries keep the public `GenerateID` scheme: every tenant user reads
  them, so there is no per-user key to MAC with.
- **A factor is only as strong as its secret.** A passphrase is stretched
  with Argon2id but can be guessed offline by anyone holding the barrier key
  and the wrapped DEK; a passkey's hmac-secret output and the recovery code
  are 256 and 160 bits and cannot.
- **Scope and sharing are access control, not organisation.** `--shared` shares
  an entry with the tenant; `--scope own|shared|all` chooses what a listing
  reveals. There is no team-scoped sharing: a user-group model belongs to
  go-qrdb and does not exist yet, so the old unwired team-scoped store, team
  REST handlers and per-tenant DAO factory were deleted.
- **Expiry is metadata, not enforcement.** `expiry.go` records
  `--expires-at`; treat an expired entry as a signal to rotate, not as a
  guarantee that the credential stopped working.
- **Tenant isolation applies.** Entries carry `--tenant-id` and the store is
  tenant-scoped — see [`../multi-tenancy/`](../multi-tenancy/architecture.md).
- **Generated passwords are only as good as the generator.** `generator.go` is
  the single source; do not add a second one at a call site.

## What this feature deliberately does not do

- **It does not encrypt shared entries itself.** Their at-rest protection is
  the barrier's; only personal entries carry the owner's own key.
- **It is not a key store.** Keys are [`../key-management/`](../key-management/architecture.md).
- **It is not the platform secret store.** Those are
  [`../platform-secrets/`](../platform-secrets/architecture.md) — platform-owned,
  sealed, not human-facing.
- **It does not own tenancy, users or teams' identity** — those come from
  go-qrdb.
- **It does not implement autofill.** The browser extension and native-messaging
  host are xkey's; this is the store behind them.
