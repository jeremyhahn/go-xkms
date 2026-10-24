# Password Vault — Architecture

> **Status: NORMATIVE** · Feature: `password-vault` · Repo: `go-xkms` · Last verified: 2026-10-24

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

`store.go`'s `DAOStore` is the only concrete `Store`: every record lives in
the go-qrdb `staticpw` database through a `GenericDAO` (`records.go`), the
system store on the composition root's datastore and each tenant's in the
store go-qrdb's tenant resolver returns for it. Shared entries are encrypted
at rest by the tenant barrier alone. A personal store additionally seals
every record body with the owner's own data key before it reaches the
barrier (see "The personal vault" below).

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
(`vault.go`, `records.go`), so reading them takes one of the user's own
factors: the tenant barrier key alone opens nothing.

```
personal entry ──AES-256-GCM(DEK, aad = storage key)──▶ tenant barrier
storage key    = {tenant}/staticpw/users/{subject}/HMAC(K_names, name)   K_names = HKDF(DEK)
DEK ──wrapped, once per factor──▶ {tenant}/staticpw-vault/users/{subject}/factors/{id}
      passphrase: KEK = Argon2id(passphrase, salt)          64 MiB, t=3, p=4 (kdf.DefaultParams)
      passkey:    KEK = HKDF-SHA256(hmac-secret output, salt) FIDO2 hmac-secret / WebAuthn PRF
      recovery:   KEK = HKDF-SHA256(recovery code, salt)    160-bit code, one-time
      piv / certificate / tpm (key factors):
                  KEK = HKDF-SHA256(S, salt, info|fingerprint) S sealed to the key (pkg/vaultkey)
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
- **Key factors** -- a PIV card's key-management key (slot 9d), a
  certificate's key (in software, on a PKCS#11 token or in a TPM), or a TPM
  key under a named TPM policy -- are described in "Key factors".

### Key factors

A key factor's secret is one only the holder of a private key can recover.
The design keeps the DEK on the server at every step (owner-approved
2026-10-01):

| Step | Who | What |
|---|---|---|
| Enroll | client | sends the key's **public key** (PKIX DER) or **certificate**, and where it keeps the key (`key_ref`: backend, key ID, TPM policy) |
| Enroll | server | draws a fresh 32-byte secret **S** sealed to the public key (`vaultkey.Seal`), wraps the DEK under `HKDF-SHA256(S, salt, "xkms/staticpw/vault/v1/key|" + fingerprint)`, stores the sealed form (`key_challenge`), a key-check value and the SPKI SHA-256 `key_fingerprint`, and forgets S |
| Unlock | client | recovers S from `key_challenge` with the private key (`vaultkey.Open`) and sends `{factor, key_fingerprint, secret: S}` |
| Unlock | server | unwraps the DEK with S |

- **Algorithms.** EC keys (P-256/P-384/P-521): ECDH-ES -- the challenge is
  an ephemeral public key, S = `HKDF-SHA256(Z, no salt, info, 32)` with Z the
  ECDH x-coordinate, computed by `types.KDFParams.Derive`, the derivation
  every xkms backend's `DeriveKeyECDH` applies. RSA keys (2048 bits or
  more): S is random and the challenge is its RSA-OAEP-256 encryption.
- **The server cannot unlock alone.** It never holds the private key and
  keeps only the sealed form of S; `TestKeyFactor_ServerCannotUnlockAlone`
  scans the barrier for S.
- **The DEK never leaves the server**, and neither the factor's key nor the
  DEK ever reaches a browser.
- **Fingerprint and key-check.** The fingerprint selects the factor and its
  token; the key-check value (HMAC of S) lets a client tell "this is another
  key" (`vaultkey.ErrWrongKey`) from a rejected credential before it sends.
- **Self-test before enrollment.** Every client seals a throwaway secret to
  the token's own key and opens it (`vaulttoken.SelfTest`) before enrolling,
  so a token that cannot perform the algorithm -- e.g. SoftHSM (2.6 and 2.7 alike), whose
  RSA-OAEP is SHA-1 only -- is refused before the user relies on it.
- **One implementation, every client.** `pkg/vaultkey` is the wire format,
  `pkg/vaulttoken` the client side over xkms key backends (PIV through the
  PIV backends' slot 9d key, PKCS#11 tokens, TPM 2.0, software). xkmsctl,
  the xkey CLI, the xkey GUI and the browser bridge all use it.
- **TPM.** RSA decryption runs `TPM2_RSA_Decrypt` and EC agreement
  `TPM2_ECDH_ZGen`, each authorized by the key's own policy session, so a key
  under a named TPM policy recovers S only on that machine in the state the
  policy expects.

### The browser bridge (key factors in the web console)

A browser never receives a private key or a certificate upload. The console
unlocks with a key factor through the **xKey browser extension**:

```
console page --postMessage--> extension content script --runtime message-->
extension worker (adds the browser-attributed origin, top frame only)
  --native messaging, encrypted, paired--> xKey native host --IPC--> xKey app:
     1. origin must be the console: https on the server's WebAuthn relying
        party (vault status passkey_rp_id) or a subdomain; http only on localhost
     2. the page's key factors must be in the vault xKey reads itself from the
        server (same user)
     3. the user approves the request in xKey (2-minute timeout)
     4. xKey recovers S with its own key backend and UNLOCKS THE VAULT ITSELF
        over its authenticated connection
  <-- {unlocked: true} -- no key, no S, no DEK reaches the page
```

- The origin the extension forwards is the browser's (`MessageSender`),
  never a value the page wrote; a sub-frame is refused.
- A request from any other origin is refused before the user is asked.
- A daemon with no app to approve in (`xkey extension serve`) answers the
  request unsupported.
- Without the extension the console says the factor needs it
  (`XkeyExtensionUnavailableError`).
- Rejected: returning the factor secret (or the DEK) to the page for the page
  to post. The vault session is per user, so xKey unlocking over its own
  connection opens the console's session -- and nothing unlock-capable ever
  exists in the page.
- Enrolling a key factor happens in xKey or xkmsctl, which hold the key.

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
- **Removal** refuses the recovery factor and the last unlock factor
  (passphrase, passkey or key factor).
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

## Design decisions (#15): the vault over USB

SPEC row `password-vault-usb` (planned; owner item 148 (a), ruling 130). It
answers the seven questions of xkey-android #15, which closed at the unlock
body; xkey-android #55 builds the phone side. The wire table is in
[api.md](api.md#usb-transport-vault-verbs-planned). The rule throughout is
DRY: the phone runs the vault described above and does not design a second
one.

1. **Method names.** `PasswordVaultStatus`, `PasswordVaultEnroll`,
   `PasswordVaultRotate`, `PasswordVaultRemoveFactor` and
   `PasswordVaultRecover`. These are the `transport.Client` verbs
   (`pkg/api/transport/client.go:490`-`506`), sent verbatim as the USB
   transport sends its other password methods
   (`pkg/api/transport/usb/transport.go:87`-`95`).
2. **USB vault traffic is in the product.** The desktop caller is the xkey
   CLI. Its vault commands already take a `PasswordStoreClientService`
   (`xkey/cmd/xkey/cmd/password.go:105`-`117`), which the USB transport
   satisfies once it has the five methods. The scheme table has no `usb`
   entry (`xkey/cmd/xkey/cmd/xkmsd_client.go:141`-`150`), so the row adds a
   `usb://` scheme that routes `xkey password` commands to
   `sdk/go/transport/usb`. Without that scheme the methods would have no
   caller, which is the gap #15 reported. USB vault traffic stays out of
   the product until the go-trusted-platform needs are met (owner item
   148 (a), ruling 130): nothing here is dev-complete before
   go-trusted-platform, and this decision is the design that ships after
   that.
3. **A real vault on the phone, not a gate.** The USB transport proxies to
   the phone's embedded xkmsd (`pkg/api/transport/usb/transport.go:80`).
   That xkmsd runs `pkg/staticpw`'s personal vault unchanged: a random
   32-byte DEK (`pkg/staticpw/vault.go:109`) seals the user's entries. The
   DEK is wrapped once per factor with AES-256-GCM under a KEK derived from
   that factor's secret (`vault.go:554`-`570`). The phone's encrypted store
   (Android Keystore-backed) stays the layer below, as the tenant barrier
   is on a server. A Keystore gate in front of the store is rejected for
   the reason a barrier-only wrap is rejected above: the device key alone
   would then open every entry.
4. **"Per-user" is the paired desktop identity.** The JSON-RPC envelope
   carries no identity (`pkg/pairingproto/protocol.go:157`-`163`). The only
   authenticated peer identity on the channel is the desktop's Noise static
   public key, pinned at pairing
   (`pkg/trust/bootstrap/noise_session.go:133`). The phone's xkmsd keys the
   vault to the subject that key names: the hex SHA-256 of the 32-byte
   static key, in the phone's system tenant. So two desktops paired with
   one phone hold two vaults. A user ID inside the params is rejected
   because the caller asserts it and nothing authenticates it. This
   follows the transports ruling of 2026-10-18: local mode verifies
   pairing devices.
5. **Neither side verifies PRF as a separate check.** As on a server, the
   32-byte hmac-secret output is key material. It is checked by the KEK's
   HKDF (`vault.go:562`) and the AES-GCM unwrap, which refuses a wrong
   secret (`ErrVaultCredentialRejected`). The desktop evaluates hmac-secret
   with `pkg/vaultpasskey`, with user verification required ("Passkey salt
   handling" above). The phone advertises its xkmsd's configured
   `passkey_rp_id`. With none configured it answers
   `ErrVaultPasskeyUnavailable`, and the desktop refuses before it touches
   the key.
6. **Every factor `pkg/staticpw` takes.** These are passphrase, passkey,
   PIV, certificate and TPM, plus the recovery code
   (`vault.go:74`-`86`). For a key factor the phone only seals S to the
   enrolled public key (`vaultkey.Seal`, "Key factors" above). The private
   key operation runs on the desktop's token through `pkg/vaulttoken`, so
   PIV, certificate and TPM need no hardware on the phone. The phone refuses
   what `VaultCredential.validate` refuses (`vault.go:264`-`305`):
   enrolling the recovery factor gets `ErrVaultRecoveryFactor`, and an
   unknown factor or malformed secret gets `ErrVaultInvalidCredential`.
7. **The recovery code is `pkg/staticpw`'s.** It is 20 random bytes
   (160 bits, `vault.go:111`), base32 without padding, in groups of four
   joined by `-` (`vault.go:586`-`601`). It is read case-insensitively,
   with `-` and spaces ignored (`vault.go:605`-`614`). It is one-time,
   and the KEK is `HKDF-SHA256(code, salt, "xkms/staticpw/vault/v1/recovery")`
   (`vault.go:117`). A code minted on a server and one minted on the phone
   have the same format.

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
             → go-qrdb DAO (staticpw database) → the tenant barrier

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
  guarantee that the credential stopped working. xkey's GUI does delete
  expired entries hourly through `ExpiryChecker`; xkmsd does not.
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
