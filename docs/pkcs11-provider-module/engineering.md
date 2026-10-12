# PKCS#11 Provider Module — Engineering Contract

> **Status: NORMATIVE** · Feature: `pkcs11-provider-module` · Repo: `go-xkms` · Last verified: 2026-10-12

## Build

```
make build-pkcs11-module        # build/lib/libxkms_pkcs11.so
make build-pkcs11-module-fips   # build/lib/libxkms_pkcs11_fips.so
```

Both targets pass the root build's tag set (`TAG_FLAGS`), so the `WITH_*`
toggles choose the backends: `WITH_TPM2=1` (the default) compiles in
`pkg/pkcs11/module/backend_tpm2.go`, which a plain `go build` with no `-tags`
silently leaves out. `GOFIPS140` is honoured by the build. The artifact is
a Cryptoki `.so`; there is no separate binary.

## Exported surface

The exported surface is **the Cryptoki C ABI**, not a Go API:

| File | Contents |
|---|---|
| `cmd/pkcs11-module/exports.go` | 92 `C_*` functions — the PKCS#11 v3.0 set |
| `cmd/pkcs11-module/exports_v32.go` | 12 `C_*` functions — the v3.2 additions |
| `cmd/pkcs11-module/function_list.go` | the dispatch table returned by `C_GetFunctionList` |
| `cmd/pkcs11-module/mechparam.go` | mechanism-parameter marshalling across the CGO boundary |
| `cmd/pkcs11-module/offline.go` | offline-mode wiring and its environment contract |
| `cmd/pkcs11-module/include/` | headers |

Go-side logic is `pkg/pkcs11/module` (sessions, objects, mechanisms, crypto,
errors), `pkg/pkcs11/localseal` (offline at-rest), `pkg/pkcs11/manager` (token
management), and `pkg/pkcs11state.Store` for the remote state plane.

### `pkg/pkcs11state`

| Name | Contract |
|---|---|
| `NewStore(daos *qrdbsdk.DAOFactory) (*Store, error)` | `daos` must serve `DatabaseName` (`"pkcs11state"`); over xkmsd's embedded node the datastore runs every DAO call as the service principal (`datastore.WithCallContext`) |
| `Put`, `PutIfAbsent`, `CompareAndSwap`, `CompareAndDelete`, `Get`, `Delete`, `List` | each takes `(ctx, tenantID, token, key, ...)`; the guarded three follow `storage.CompareAndSwapper` / `CompareAndDeleter`: an absent record refuses, a nil `expected` matches only a stored empty value |
| `Record{ID, Name, Scope, Key, Value}` | the `pkcs11_state_records` entity; `Name` is `<tenant>/<token>/<key>` |
| `ErrNilDAOFactory` | `NewStore` without a factory |
| `StoreError{Op, Key, Err}` | any store failure; `Op` is `open`, `put`, `put-if-absent`, `compare-and-swap`, `compare-and-delete`, `get`, `delete` or `list`. A failed guarded write's outcome is unknown, so it is never reported as a refusal |

### Go surface for CGO-free callers

| Name | Contract |
|---|---|
| `ProvisionECKeyPair(ctx, ProvisionConfig, KeyPairRequest) (*ProvisionedKeyPair, error)` | create a P-256 or P-384 key pair with the requested `CKA_LABEL`/`CKA_ID` on the token; initializes an uninitialized token with `SOPIN` and sets the user PIN; idempotent |
| `ProvisionConfig{Client, Storage, Backend, Timeout}` | the key service transport, the token store, the backend that holds the key |
| `KeyPairRequest{Label, ID, Curve, UserPIN, SOPIN, TokenLabel}` | the key to create |
| `ProvisionedKeyPair{Label, ID, KeyID, Backend, Curve, PublicKey, Created}` | `KeyID` is what a sign request names; `Created` is false for an existing identical key |
| `NewRemoteStorage(client PKCS11StateClient, tenantID, token)` | the token store a remote-mode module reads |
| `ProvisionError{Step, Err}` | the Cryptoki step that failed |

Idempotency: the same label, id and curve returns the existing key with
`Created` false. A different key under either the label or the id, or the same
pair on another curve, is `ErrProvisionKeyConflict` and nothing is created.
Other sentinels: `ErrProvisionClientRequired`, `ErrProvisionStorageRequired`,
`ErrProvisionLabelRequired`, `ErrProvisionIDRequired`,
`ErrProvisionCurveUnsupported`, `ErrProvisionUserPINRequired`,
`ErrProvisionSOPINRequired`, `ErrProvisionECPoint`. A wrong PIN surfaces as the
module's `ErrPINIncorrect` under `ProvisionError{Step: "C_Login(CKU_USER)"}`.
The same names are re-exported by `sdk/go/signserver`.

### `pkg/pkcs11/manager`

Loads third-party Cryptoki libraries and manages their tokens for the CLI and
GUI. The real implementation is build-tagged `pkcs11`
(`manager_pkcs11.go:1`); without the tag every call returns
`ErrPKCS11Disabled` (`errors.go:21`, `manager_stub.go`).

| Name | Contract |
|---|---|
| `New(opts ...Option) Manager` (`manager_pkcs11.go:54`), `WithLogger` (`manager.go:264`) | constructor |
| `Manager` (`manager.go:48-97`) | `IsAvailable`, `RegisterModule(path, name) (id, error)`, `UnregisterModule`, `RefreshSlots` (hot-plug), `GetModule`, `ListModules`, `ListTokens`, `InitializeToken(id, slot, label, soPin, userPin)` (`C_InitToken` + `C_InitPIN`), `TestLogin`, `Connect(id, slot, userPin, soPin) (Backend, error)`, `Disconnect`, `GetConnection`, `ListConnections`, `Close` |
| `ProbeModulePaths`, `ProbeModulesWithNames` (`probe.go:84`, `:102`) | find installed Cryptoki libraries |
| `DeriveModuleID` (`probe.go:191`), `DetectDevice` (`detect.go:61`) | stable module ID; device type, `IsHardwareBacked` (`:149`) |

## Configuration — environment and an optional file

Cryptoki consumers cannot pass configuration, so the module reads it itself.
Constants are in `pkg/pkcs11/module/config.go` (environment names at `:48-61`)
and `cmd/pkcs11-module/offline.go`.

- **Remote mode** — `C_Initialize` (`cmd/pkcs11-module/exports.go:226`) calls
  `Module.Initialize(nil)`, which runs `Load()` (`module.go:496`) →
  `LoadWithPath(DefaultConfigPath)` (`config.go:632-663`). That reads the INI
  file `/etc/xkms/pkcs11.conf` (`config.go:34`) **if it exists**
  (`LoadFromFile`, `:532`), then applies the environment over it
  (`applyEnvOverrides`, `:666` — **the environment wins**), fills defaults and
  validates. Any failure answers `CKR_GENERAL_ERROR` (`module.go:498`).
- **Offline mode** reads the environment only (`LoadFromEnv`, `offline.go:162`,
  `config.go:431`).

The file is refused unless its mode grants nothing to group or other
(`checkConfigFilePermissions`, `config.go:507-512`, `ErrConfigFilePermissions`).
Its keys (`config.go:588-620`) mirror the remote-mode variables below:
`target`, `tls_enabled`, `tls_cert`, `tls_key`, `tls_ca`,
`allow_insecure_transport`, `timeout`, `default_backend`, `auto_init_token`,
`so_pin`, `user_pin`, `token_label`, `storage_type`, `storage_path`,
`piv_backends`. `TenantID` (`config.go:158`) is settable from Go only.

Defaults: target `unix:///var/run/xkms/xkms.sock` (`config.go:40`), timeout 30s
(`:37`), backend `software` (`:43`).

`Validate` (`config.go:203`) refuses: a nil config (`ErrNilConfig`, `:205`), an
empty target (`ErrEmptyTarget`, `:209`), a non-`unix://` target without TLS
unless insecure transport is allowed (`ErrInsecureRemoteTarget`, `:228`;
`isLocalTarget`, `:252-254`), a non-positive timeout (`ErrInvalidTimeout`,
`:233`), inconsistent storage settings (`:319-333`), incomplete TLS material
(`:342-362`), and an MCP target (`ErrMCPTargetNotSupported`, `:405`).

### Mode selection

| Variable | Values | Default |
|---|---|---|
| `XKMS_PKCS11_MODE` | `local` / `offline` → offline mode; **anything else, including unset → remote** | remote |
| `XKMS_PKCS11_LOCAL_KEYDIR` | offline key material location | `<StoragePath>/keys`, else a standard dir |
| `XKMS_PKCS11_SEAL_STRATEGY` | `passphrase` \| `none` | **`passphrase`** |

`XKMS_PKCS11_SEAL_STRATEGY=passphrase` keys offline key material under the user
PIN via go-qrdb's barrier. `none` stores it in **cleartext**, matching SoftHSM's
unencrypted default — development and test only. `offlineSealStrategy()`
defaults to `passphrase`: only the exact string `none` (case-insensitive,
trimmed) opts out.

The offline root key path is `pkcs11/token/root-key`.

### Offline module lifecycle

`C_Initialize` in offline mode goes through `initializeOffline()`, which holds
one lock while it decides, builds, installs and initializes. It builds the
embedded service and a module wired to it when no global module is installed,
and **rebuilds** it when the installed module is the one the library built and
has been finalized: `C_Finalize` closes and drops the embedded client and the
object store, so that module cannot come back up on its own. PKCS#11 v3.2 §5.4
allows initializing again after `C_Finalize`, and `p11-kit server` always does
it (a probe initialize and finalize, then the RPC client's initialize). A global
module a Go caller installed (xkey) is never replaced; it is initialized as it
is. The token itself lives in the key and state directories, so a rebuilt module
sees the same token, PINs and keys.

### Remote mode and token identity

| Variable | Purpose |
|---|---|
| `XKMS_PKCS11_TARGET` | the xkmsd endpoint |
| `XKMS_PKCS11_TLS_ENABLED` | enable TLS |
| `XKMS_PKCS11_TLS_CERT` / `_TLS_KEY` / `_TLS_CA` | client mTLS material |
| `XKMS_PKCS11_TIMEOUT` | operation timeout |
| `XKMS_PKCS11_ALLOW_INSECURE_TRANSPORT` | **defaults off**; enabling sends token operations unauthenticated |
| `XKMS_PKCS11_DEFAULT_BACKEND` | which keystore backend the token's keys use |
| `XKMS_PKCS11_SO_PIN` / `XKMS_PKCS11_USER_PIN` | PINs — no prompt is possible in this context |
| `XKMS_PKCS11_TOKEN_LABEL` | token label presented to consumers |
| `XKMS_PKCS11_AUTO_INIT_TOKEN` | initialize the token on first use |
| `XKMS_PKCS11_STORAGE_TYPE` / `_STORAGE_PATH` | state storage |
| `XKMS_PKCS11_PIV_BACKENDS` | PIV backends exposed through the token; see [PIV objects](#piv-objects) |
| `XKMS_PKCS11_ALLOW_WEAK_HASH_SIGNING` | `true`/`1`/`yes`/`on` keeps `CKF_SIGN` on `CKM_SHA1_RSA_PKCS` and `CKM_ECDSA_SHA1`; otherwise they advertise verify only (`mechanism.go:2351-2376`). Both modes |

**Build-tag trap, documented at `config.go:266`:**
`XKMS_PKCS11_DEFAULT_BACKEND=vault` fails `C_Initialize` when the module was
built without the `vault` tag. The backend set is fixed at build time; the
environment can only select from what was compiled in. A `C_Initialize` failure
naming a backend is this, not a configuration typo.

## Invariants

- **`C_Initialize` fails closed.** An unreachable target, an unavailable
  backend, a missing tag, or unusable storage all fail initialization rather
  than degrading. A consumer that got a function list has a working token.
  Loading PIV objects is the one best-effort step (see [PIV objects](#piv-objects)).
- **The module never builds its own sealer.** Offline at-rest protection uses
  go-qrdb's barrier (`offline.go`). A local sealer would be a second,
  unreviewed barrier.
- **The secure seal strategy is the default.** `passphrase` unless explicitly
  set to `none`.
- **`CKR_FUNCTION_NOT_SUPPORTED` is a contract, not a failure.**
  `crypto.go:3351`, `:3367` and `:3390` state the intent: the caller must be able to distinguish
  "this token will never do that" from "that operation failed". Do not collapse
  it into a generic error.
- **Remote token state is CAS-guarded.** `PKCS11StateCAS` and
  `PKCS11StatePutIfAbsent` exist so concurrent sessions cannot clobber token
  state. Use them; a plain `Put` in a concurrent path is a defect.
- **A guarded create is released by a guarded delete.** `PKCS11StateCAD`
  removes a record only if it still holds the value the caller observed, and
  the server evaluates the guard; the remote backend therefore claims
  `storage.CompareAndDeleter` and never emulates the guard with a local lock,
  which would guard nothing across the hosts sharing one token. An absent key
  or a different value is a refusal (`deleted=false`, no error); an error means
  the outcome is unknown, and a caller must not read it as a refusal.
- **Remote state is namespaced by the authenticated tenant.** The service
  derives the tenant (`pkcs11StateScope`, `pkg/xkms/servicer_pkcs11state.go:79`).
  A request's `tenant_id` may be empty or the caller's own tenant. Anything else
  fails with `ErrPKCS11StateTenantMismatch`. Token labels must not contain `/`
  (`ErrPKCS11StateTokenSeparator`). Never add a transport path that passes a
  request tenant to `pkcs11state.Store`. The store has no isolation of its own
  (`pkg/pkcs11state/store.go:14-24`).
- **Session and object handles are per-process.** They are not portable across
  processes even in remote mode, where the *state* is shared but the handles are
  not.
- **The PIN budget is shared by every process on the token.** An attempt is
  charged to the durable counter before its PIN is checked, and a store
  failure refuses the login; see [PIN lockout](#pin-lockout).
- **Concurrency.** Cryptoki permits concurrent sessions; the module serialises
  where the backend requires it and relies on CAS for shared state.
- **A named curve is never substituted.** Where a template carries
  `CKA_EC_PARAMS`, `C_GenerateKeyPair` and `C_UnwrapKey` both resolve it through
  `extractCurveFromParams` and both answer a value the module does not
  recognise with `CKR_CURVE_NOT_SUPPORTED`. Producing a key on a different
  curve than the caller named is a dropped parameter, not a default. An
  **absent** `CKA_EC_PARAMS` is not an error on the unwrap path: v3.2 Table 13
  footnote 6 says an EC private key's must not be specified there, so the
  service's own default stands for a caller that sends none.

## Error semantics

`pkg/pkcs11/module/errors.go` maps Go errors to `CK_RV` values and back:
`NewPKCS11ErrorWithMessage(rv, msg)`, `NewPKCS11ErrorFull(...)`,
`backendCKRV(err, fallback)`. Every `CKR_*` constant has a string form and a Go
sentinel — `CKR_FUNCTION_NOT_SUPPORTED` (`0x00000054`) ↔ `ErrFunctionNotSupported`.

**Fail-closed paths:** `C_Initialize` with an unreachable or uncompiled backend;
any operation before `C_Login` where the mechanism requires it; a CAS conflict
on token state; an unusable offline key directory.

**`GODEBUG=fips140=only` and authenticated wrapping:** Go's `crypto/cipher`
refuses arbitrary-IV GCM in the only mode (not under `fips140=on`, where it
works), and every parameter form of `C_WrapKeyAuthenticated` /
`C_UnwrapKeyAuthenticated` supplies an IV — the token-generated form included.
The three verbs (wrap, size query, unwrap) refuse at the mechanism check with
`CKR_MECHANISM_INVALID` before any handle is resolved, instead of surfacing the
runtime refusal from inside the wrap as `CKR_FUNCTION_FAILED` (#292). The gate
is `aead.ArbitraryIVGCMUsable`, a cached runtime probe rather than a FIPS
predicate, because `fips140.Enabled()` is true under both modes and no exported
predicate names the only mode. `CKM_AES_GCM` stays in `C_GetMechanismList`: its
`C_Encrypt` / `C_Decrypt` / `C_WrapKey` surface performs GCM in the service
process, whose own FIPS posture governs it.

## Persistence

- **Remote mode** — token and object state through `pkg/pkcs11state.Store` over
  the `PKCS11State*` RPCs: one `pkcs11_state_records` DAO entity per record in
  the `pkcs11state` go-qrdb database, named `<tenant>/<token>/<key>`, with the
  system scope under `system/<token>/`. xkmsd opens the database and writes it
  as the embedded node's service principal.
- **Offline mode** — key material under `XKMS_PKCS11_LOCAL_KEYDIR`, protected by
  `pkg/pkcs11/localseal` per `XKMS_PKCS11_SEAL_STRATEGY`, rooted at
  `pkcs11/token/root-key`.

Handles are ephemeral; state is durable. A restart re-derives handles from state.

### CKM_ECDSA and caller-supplied digests

CKM_ECDSA signs a digest the caller built, so the module sends the digest under
hash `"NONE"`. Since Go 1.27, `ecdsa.PrivateKey.Sign` refuses
`crypto.Hash(0)`, and a TPM or PKCS#11 signer derives its scheme from the hash.
The service therefore names the SHA-2 function the digest length implies: 28,
32, 48 or 64 bytes map to SHA-224, SHA-256, SHA-384 or SHA-512. Any other
length, including SHA-1's 20, is refused with `ErrInvalidHashFunction`.

### Confirmed mechanisms and lookup

The sequence an IKE daemon (strongSwan's pkcs11 plugin) issues is verified
through the C ABI against a remote-mode token served by
[`../sign-server/`](../sign-server/engineering.md), and in Go by the
`pkg/signserver` tests: `C_GetFunctionList`, `C_Initialize` with
`CKF_OS_LOCKING_OK`, `C_GetSlotList`, `C_OpenSession`, `C_Login(CKU_USER)`,
`C_FindObjects` by `CKA_CLASS`+`CKA_LABEL` and by `CKA_CLASS`+`CKA_ID` (both
naming the same object), `C_SignInit(CKM_ECDSA)`, then `C_Sign` with a length
query and the real call. The signature is raw `r || s`: 64 bytes on P-256, 96 on
P-384, and it verifies under OpenSSL.

## PIN lockout

The PIN budget belongs to the token, not to the process: every process that
opens the same token shares one counter per PIN (`MaxPINAttempts`,
3, `pkg/pkcs11/module/session.go:1204`) under the dedicated keys
`pkcs11/counters/token/<slot>/failed_{user,so}` (`storage.go:220`).

- **An attempt is spent before it is checked** (#1144).
  `finishPINVerification` (`session.go:1169`) charges the attempt through the
  `AttemptLedger` (`session.go:733`) and runs the Argon2id derivation only if
  the ledger admits it. A wrong PIN leaves the attempt spent; a correct one is
  refunded. The ledger's answer is the only thing that admits a derivation,
  so a process whose cached count is stale cannot verify a PIN, or clear a
  lock, once the shared counter is exhausted.
- **The spend is a guarded write.** `ModuleStorage.SpendFailedAttempt`
  (`storage.go:270`) increments only while the counter is below the limit, and
  writes nothing once it is not. It runs through `updateViaCAS`
  (`storage.go:333`): `PutIfAbsent` creates the key, and `CompareAndSwap`
  retries against the value the failed swap observed. Remote tokens reach the
  server's compare-and-swap through `PKCS11StateCAS` (`storage_remote.go:136`,
  `pkg/pkcs11state/store.go:145`), so the guard holds across hosts.
- **A local file token's guard holds across processes, not only goroutines**
  (#1157). `StorageTypeFile` opens `pkg/storage/file.FileStorage`, whose
  `Put`, `Delete`, `PutIfAbsent`, `CompareAndSwap` and `CompareAndDelete` each
  hold an advisory `flock` on the token directory itself
  (`pkg/storage/file/lock.go`) for the whole guarded read-compare-write, as
  does opening the store.
  Before this, the wrapped engine's atomicity (`pkg/storage/engine.go`'s
  `engineBackend`, still the in-process guarantee this lock is layered over)
  was a process-local mutex: two module instances pointed at the same file
  token directory could interleave their `SpendFailedAttempt` read and write
  and both succeed, undercounting the shared budget. See
  [`../datastore/engineering.md`](../datastore/engineering.md)
  for the lock's design.
- **A refund never erases someone else's failure.**
  `RefundFailedAttempt` (`storage.go:283`) applies `refundedCount`
  (`session.go:1352`). If nothing touched the counter since the spend, it resets
  to zero, because a success ends the run of consecutive failures. If later
  attempts were charged, only this attempt's own charge is returned. If the
  counter was reset underneath, nothing is returned.
- **The ledger fails closed.** An error from the spend or the refund answers
  `CKR_DEVICE_ERROR` and grants nothing. The cause is recorded through
  `LastStorageError` by `tokenAttemptLedger` (`module.go:293`). `C_InitToken`, `C_InitPIN` and
  `C_SetPIN` answer `CKR_DEVICE_ERROR` when the counter reset they perform does
  not reach the store (`ResetPINAttempts`, `session.go:1367`).
- **The in-memory counters are a cache.** With a store configured they only
  feed the `CKF_*_PIN_*` flags in `CK_TOKEN_INFO` (`PINAttemptStatus`,
  `session.go:1452`). Those flags show the last value this process saw. A
  module with no store (`ModuleStorage.Durable` false) keeps the budget in
  memory, with the same spend-first rule.
- **Limits.** A correct PIN that succeeds while other processes are mid-guess
  can reset their in-flight charges. That is the normal "a success resets the
  budget" rule, applied during a race. The file engine's compare-and-swap is
  atomic only within one process (`pkg/storage/engine.go:68`). Two processes
  on one *file* token therefore always see each other's attempts, but a
  read-modify-write that interleaves within one swap can still lose an update.
  Remote tokens have no such window.

## Interfaces and v3.2 status

`C_GetInterface` (`exports.go:320-382`) accepts only the name `"PKCS 11"`
(`:350`) and refuses any non-zero flags, `CKF_INTERFACE_FORK_SAFE` included
(`:338`). A NULL name or version returns v3.2; version 2 returns the v2.40
list, 3.0 the 3.0 list, 3.2 the 3.2 list; anything else is
`CKR_ARGUMENTS_BAD`. The v3.2 functions are only in `functionList32`
(`function_list.go:342`; `C_EncapsulateKey` at `:443`).

Implemented v3.2 surfaces:

| Surface | Where |
|---|---|
| KEM — `C_EncapsulateKey` / `C_DecapsulateKey` | `module_kem.go`, `module_kem_quantum.go` |
| Authenticated wrapping | `module_authwrap.go:429` (wrap), `:853` (unwrap) |
| Signature-first verification — `C_VerifySignature*` | `module_verifysig.go:49`, `:151`, `:206`, `:254` |
| `C_GetSessionValidationFlags` | `module_validation.go:58-83` |

Authenticated wrap refuses a wrapping key whose value is shorter than the
target key's with `CKR_WRAPPING_KEY_SIZE_RANGE`
(`requireWrappingKeyStrength`, `module_authwrap.go:109-115`); the wrap
(`:590`) and its size query (`:780`) apply it, unwrap and plain `C_WrapKey`
do not.

Only these answer `CKR_FUNCTION_NOT_SUPPORTED`: the asynchronous functions
(`module_async.go:58`, `:78`, `:94`, `:114`, `:131`, `:151`) and
`C_WaitForSlotEvent` without `CKF_DONT_BLOCK` (`exports.go:2081-2087`). The
message-based signature-first verification functions
(`C_MessageVerifySignatureInit` and its siblings) do not exist; ordinary message
verification does (`module.go:5466-5669`). Changes from v3.0:
[`../references/pkcs11-v3.0-to-v3.2-changes.md`](../references/pkcs11-v3.0-to-v3.2-changes.md).

## Mechanisms

Three registries describe every mechanism: `mechanismRegistry`
(`mechanism.go:1362`, 48 entries), `v32MechanismRegistry`
(`mechanism_v32.go:271`, 34, merged at `mechanism.go:686-691`) and
`quantumMechanismRegistry` (`mechanism_quantum.go:196`, 15, merged at
`:373-380`). 46 of the 97 are advertised. The descriptor at each cited line is
the authority for flags and key sizes.

`C_GetMechanismList` / `C_GetMechanismInfo` read `defaultMechanismInfo`
(`token.go:1026-1054`): unadvertised entries are skipped, non-FIPS entries are
skipped when FIPS mode is on (`:1035`), and key sizes and flags come from
`effectiveKeySizeRange` (`mechanism.go:2478-2486`) and
`effectiveMechanismFlags` (`:2385-2390`).

| Family | Advertised (`mechanism.go` line) |
|---|---|
| RSA | `CKM_RSA_PKCS_KEY_PAIR_GEN` 1370, `CKM_RSA_PKCS` 1381, `CKM_RSA_PKCS_OAEP` 1434, `CKM_RSA_PKCS_PSS` 1447, `CKM_SHA1_RSA_PKCS`\* 1460, `CKM_SHA256/384/512_RSA_PKCS` 1471/1482/1493, `CKM_SHA256/384/512_RSA_PKCS_PSS` 1504/1517/1530 |
| EC | `CKM_EC_KEY_PAIR_GEN` 1550, `CKM_ECDSA` 1560, `CKM_ECDSA_SHA1`\* 1584, `CKM_ECDSA_SHA224/256/384/512` 1593/1603/1613/1623, `CKM_ECDH1_DERIVE` 1639, `CKM_ECDH1_COFACTOR_DERIVE` 1668 |
| EdDSA | `CKM_EC_EDWARDS_KEY_PAIR_GEN` 1687, `CKM_EDDSA` 1697 (FIPS-approved, `:1700`) |
| AES | `CKM_AES_KEY_GEN` 1763, `CKM_AES_ECB` 1773, `CKM_AES_CBC` 1797, `CKM_AES_CBC_PAD` 1809, `CKM_AES_GCM` 1821, `CKM_AES_KEY_WRAP` 1840, `CKM_AES_KEY_WRAP_KWP` 1860, `CKM_AES_KEY_WRAP_PAD` 1870 |
| Digest | `CKM_SHA_1` 1888, `CKM_SHA256` 1896, `CKM_SHA384` 1904, `CKM_SHA512` 1912, `CKM_SHA224` 1920, `CKM_SHA512_224` 1939, `CKM_SHA512_256` 1947 |
| KDF | `CKM_HKDF_DERIVE`\* 2048, `CKM_HKDF_DATA`\* 2059, `CKM_SP800_108_COUNTER_KDF` 2089, `CKM_SP800_108_FEEDBACK_KDF` 2101, `CKM_SP800_108_DOUBLE_PIPELINE_KDF` 2113 |
| PQC (`mechanism_v32.go`) | `CKM_ML_KEM_KEY_PAIR_GEN` 276, `CKM_ML_KEM` 293, `CKM_ML_DSA_KEY_PAIR_GEN` 315, `CKM_ML_DSA` 327 (advertised at `:286`, `:304`, `:322`, `:334`) |

\* Not FIPS-approved: withheld from both list and info in FIPS mode. SHA-1 and
ECDSA-SHA1 signing is additionally withheld unless
`XKMS_PKCS11_ALLOW_WEAK_HASH_SIGNING` is set (`weakHashSignatureMechanisms`,
`mechanism.go:2358-2361`). RSA keys are 2048 (`:1331`) to 4096 bits (`:1351`),
3072 at most in FIPS mode (`:1358`).

Registered but **not advertised** (`mechanismsAwaitingAnImplementation`,
`mechanism_conformance_test.go:312`, reasons at `:322-339`):

| Mechanism | Reason |
|---|---|
| `CKM_RSA_X_509` (`mechanism.go:1425`) | only verify-recover is performed (`CKF_VERIFY_RECOVER`, `:1432`) |
| `CKM_SHA256/384/512_HMAC` (`:2001`, `:2009`, `:2017`) | no backend performs a symmetric MAC; the constants remain KDF PRF selectors |
| `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` (`:1714`) | no backend generates an X25519/X448 pair |
| `CKM_GENERIC_SECRET_KEY_GEN` (`:2153`) | generates only AES sizes, so no truthful key-size range exists |
| the rest of `mechanism_v32.go` (HashML-DSA `351-431`, SLH-DSA `441`/`448`, HashSLH-DSA `471-531`, HSS `539`/`546`, XMSS `563`/`570`, XMSS^MT `587`/`594`) and every vendor entry in `mechanism_quantum.go` (ML-DSA-44/65/87 `202-251`, ML-KEM-512/768/1024 `285-361`) | descriptors with no end-to-end operation |

`TestNoMechanismIsUndiscoverableButUsable` (`mechanism_conformance_test.go:356`)
and `TestEveryDigestMechanismIsBothRegisteredAndImplemented` (`:72`) keep the
list and the implementations aligned. There is no SHA-3 digest, HMAC or CMAC
signing, AES-CTR or AES-CCM, and no DSA, DH, DES, RC2, RC4 or IDEA mechanism.

### Key derivation

`C_DeriveKey` sends the base key's `CKA_VALUE` when it has one, otherwise its
backend key identifier, so the KDF runs inside the backend over the key it
already holds (`module.go:7672-7675`). A base key with neither is
`CKR_KEY_HANDLE_INVALID`. Backends implementing `types.SymmetricKeyDeriver`
(`pkg/types/kdf.go:137`): software (`pkg/backend/software/software.go:458`),
the symmetric key provider (`pkg/keyprovider/symmetric/kdf.go:42`), TPM 2.0
(`pkg/backend/tpm2/kdf.go:50`) and PKCS#11 (`pkg/backend/pkcs11/pkcs11_kdf.go:48`).
A derivation naming any other backend is refused.

### Daemon policy

Advertising is the module's; performing is the daemon's. Two `crypto` settings
in `pkg/config/config.go` refuse operations the module still lists:

- `allow_weak_hashes` (`:120`, default off) refuses SHA-1 signing in the
  service layer.
- `allow_legacy_key_wrap` (`:143`, default off) refuses `CKM_RSA_PKCS`,
  `CKM_AES_CBC_PAD` and `CKM_AES_CBC` for wrap/unwrap and RSA PKCS#1 v1.5
  decrypt (`pkg/xkms/servicer_wrapkey.go:105`, `:179`, `:651`, `:720`, `:832`;
  `servicer_crypto.go:773`, `:788`, `:838`, `:987`); xkmsd warns when it is on
  (`pkg/server/server.go:621`). In FIPS mode `types.SetAllowLegacyKeyWrap`
  ignores a request to enable it (`pkg/types/wrappolicy.go:93-97`).

## Deviations and limits

- **Init gates on registration only.** `validateInitMechanism`
  (`module.go:2984-2992`) checks `GetMechanismDescriptor`, so a registered but
  unadvertised mechanism passes `C_*Init` and fails at the operation.
- **No raw RSA sign or decrypt.** `CKM_RSA_X_509` is verify-recover only.
- **RSA-PSS** (`validateRSAPSSParams`, `crypto.go:1206-1250`): parameters are
  required; `hashAlg` must match the mechanism's hash; `mgf` must be the
  matching MGF1; `sLen` 0 is `CKR_MECHANISM_PARAM_INVALID`. There is no upper
  bound on `sLen`.
- **RSA-OAEP** (`ValidateRSAOAEPParams`, `mechanism.go:766-786`): `mgf` 0 or the
  matching MGF1; `source` 0 or `CKZ_DATA_SPECIFIED`, which source data requires.
- **ECDH peer points** (`ValidateECDHPeerPoint`, `mechanism.go:967-982`) must be
  uncompressed (`0x04`), of the curve's length and on the curve, else
  `CKR_MECHANISM_PARAM_INVALID`.
- **Caller-supplied digests.** `CKM_RSA_PKCS` and `CKM_ECDSA` are sent with hash
  `"NONE"` (`crypto.go:2218-2282`).
- **One-way attributes.** Once reached, `CKA_SENSITIVE` and
  `CKA_WRAP_WITH_TRUSTED` true, and `CKA_EXTRACTABLE` and `CKA_COPYABLE` false,
  cannot be reversed (`oneWayBoolAttributes`, `object.go:914-919`;
  `checkOneWayTransition`, `:928`). Setting `CKA_TRUSTED` is SO-gated, and a
  trusted certificate is immutable (`checkTrustedAssertion`, `:964-974`).
- **Objects are not slot-scoped** (`destroyTokenObjects`, `module.go:3021`).
- **`C_InitToken` on an initialized token** requires its existing SO PIN
  (`module.go:1447-1448`).
- **`*Update` length queries** do not consume input (`exports.go:1000`,
  `:1144`).
- **No fork safety**; `CKF_INTERFACE_FORK_SAFE` is refused.
- **Finalize** destroys session objects and zeroizes the object manager
  (`module.go:1079`, `:1087`; `ObjectManager.Zeroize`, `object.go:3212`).
  `C_CloseAllSessions` destroys the slot's session objects (`module.go:1796`).

## PIV objects

With `piv_backends` set, `Initialize` calls `LoadPIVObjects`
(`module_piv.go:304`) for each listed backend (`module.go:597-607`). This is
**best effort**: a failure is logged (`logInitWarning`, `:605`) and does not
fail `C_Initialize`.

Each occupied slot yields a certificate, public key and private key sharing
`CKA_ID` = first 20 bytes of SHA-256 over the certificate's SubjectPublicKeyInfo
(`computePIVObjectID`, `module_piv.go:265-267`) and `CKA_LABEL` `piv:<slot>`
(`:358`).

| Object | Attributes |
|---|---|
| Certificate | `CKA_SUBJECT`, `CKA_ISSUER`, `CKA_SERIAL_NUMBER`, `CKA_PRIVATE` false (`:394-408`) |
| Public key | `CKA_PRIVATE` false, `CKA_VERIFY`, `CKA_ENCRYPT` (`:427-429`) |
| Private key | `CKA_PRIVATE` per slot, `CKA_SENSITIVE`, `CKA_SIGN`, `CKA_DECRYPT`, `CKA_EXTRACTABLE` false, `CKA_NEVER_EXTRACTABLE`, `CKA_ALWAYS_SENSITIVE` (`:458-465`) |

Slot policy (`pivSlotPolicies`, `:124-126`): `9c` is private with
`CKA_ALWAYS_AUTHENTICATE`; `9e` is not private; every other slot is private
(`:132`). A slot's objects are replaced, not accumulated
(`DestroyObjectsForKey`, `:366`), and `DeletePIVCertificate` removes them
(`:679`). The Go methods `StorePIVCertificate`, `DeletePIVCertificate`,
`ImportPIVCertificate`, `ExportPIVCertificate`, `GeneratePIVCSR` and
`GeneratePIVKeyPair` (`:489`) maintain the objects; no Cryptoki function routes
to `GeneratePIVKeyPair`, and its private key is always `CKA_PRIVATE` true
(`:561`).

## Test strategy

- **Unit** — `cmd/pkcs11-module/exports_test.go`, `exports_twocall_test.go`
  (the Cryptoki two-call idiom, where the first call sizes the buffer),
  `exports_random_test.go`, `offline_test.go`; and the large
  `pkg/pkcs11/module` suite, including per-v3.2-surface tests
  (`module_kem_test.go`, `module_authwrap_*_test.go`,
  `module_verifysig_*_test.go`, `module_async_test.go`). The cross-process
  lockout is pinned by `session_pin_ledger_test.go`. Two `Module` values over
  one backend stand in for two processes, sharing the same in-process
  `storage.Backend`, so this suite pins the ledger's semantics rather than
  cross-process file-lock atomicity. The tests cover the shared budget, a
  stale instance, concurrent guessing (counted by derivations), a reset on
  success, and a store fault. Each runs for both the user PIN and the SO PIN.
  `pkg/pkcs11/module/storage_crossprocess_test.go`'s
  `TestModuleStorage_FailedAttemptCounter_CrossProcessAccumulates` is the
  genuinely cross-process counterpart (#1157): it re-execs the test binary as
  several real OS processes sharing one `StorageTypeFile` token directory,
  each spending failed attempts concurrently, and asserts the durable counter
  is the exact combined total.
- **Remote state store** — `pkg/pkcs11state/store_test.go` round-trips every
  operation through a real in-process DAO, survives a reopen over the same
  store, and races 32 `PutIfAbsent` writers and 16 `CompareAndSwap`
  incrementers to prove exactly one create and no lost update. It also pins
  each operation's `StoreError` on a failing store and that every call runs on
  the bound context.
- **Tenant isolation of remote state** —
  `pkg/xkms/servicer_pkcs11state_tenant_test.go` drives all seven operations
  through one table and checks four things. A foreign or `system` tenant is
  refused. The caller's own tenant, stated or omitted, is accepted. A `/` in the
  token is refused. Two tenants using the same token and key stay isolated.
  Transport tests: `pkg/api/rest/pkcs11state_tenant_handler_test.go` (400) and
  `pkg/api/grpc/service_pkcs11state_tenant_test.go` (`InvalidArgument`, which
  also covers Unix).
- **Integration** — `test/integration/pkcs11`, driving real consumers.
- **Compatibility** — the two-call convention and mechanism-parameter
  marshalling are the fragile CGO seams and have dedicated suites.
- **Conformance under `GODEBUG=fips140=only`** — `TestPKCS11V3Suite` runs the
  shared `pkg/testing/pkcs11test` suite against a module whose backend is the
  in-process `CryptoMockClient`. That mock answers a raw `CKM_RSA_PKCS`
  `C_Sign` / `C_SignRecover` (hash `NONE`) the way the service does: with
  `types.ErrRawPKCS1v15Enforced`, so the verb fails as `CKR_FUNCTION_FAILED`
  instead of dying in `crypto/rsa`, which panics on `crypto.Hash(0)` in the
  only mode and used to abort the whole test binary (#486). Expectations that a
  non-approved form succeeds — the `SignRecover` happy path among them — are
  therefore ordinary failures in that mode, not crashes; the mock's own
  `crypto_mock_client_fips_test.go` re-execs under both modes to hold that.

## Observability

The module logs into the consumer's process, which is a constraint rather than a
choice — it cannot assume a log destination. Failures surface as `CK_RV` values,
so `CKR_*` codes are the primary diagnostic; keep the string mapping in
`errors.go` complete, because a bare hex code in a consumer's log is otherwise
unreadable.
