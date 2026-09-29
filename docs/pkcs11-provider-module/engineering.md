# PKCS#11 Provider Module — Engineering Contract

> **Status: NORMATIVE** · Feature: `pkcs11-provider-module` · Repo: `go-xkms` · Last verified: 2026-09-29

## Build

```
CGO_ENABLED=1 go build -buildmode=c-shared -o build/lib/libxkms_pkcs11.so ./cmd/pkcs11-module
```

`GOFIPS140` is honoured by the build (`Makefile:2004`, `:2011`). The artifact is
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
management), and `pkg/pkcs11state.Store` (`NewStore(backend storage.Backend)`)
for the remote state plane.

## Configuration — environment only

Cryptoki consumers cannot pass configuration, so everything is environment.
Constants are in `pkg/pkcs11/module/config.go` and
`cmd/pkcs11-module/offline.go`.

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
| `XKMS_PKCS11_PIV_BACKENDS` | PIV backends exposed through the token |

**Build-tag trap, documented at `config.go:266`:**
`XKMS_PKCS11_DEFAULT_BACKEND=vault` fails `C_Initialize` when the module was
built without the `vault` tag. The backend set is fixed at build time; the
environment can only select from what was compiled in. A `C_Initialize` failure
naming a backend is this, not a configuration typo.

## Invariants

- **`C_Initialize` fails closed.** An unreachable target, an unavailable
  backend, a missing tag, or unusable storage all fail initialization rather
  than degrading. A consumer that got a function list has a working token.
- **The module never builds its own sealer.** Offline at-rest protection uses
  go-qrdb's barrier (`offline.go`). A local sealer would be a second,
  unreviewed barrier.
- **The secure seal strategy is the default.** `passphrase` unless explicitly
  set to `none`.
- **`CKR_FUNCTION_NOT_SUPPORTED` is a contract, not a failure.**
  `crypto.go:3327` states the intent: the caller must be able to distinguish
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
  the `PKCS11State*` RPCs, into go-qrdb.
- **Offline mode** — key material under `XKMS_PKCS11_LOCAL_KEYDIR`, protected by
  `pkg/pkcs11/localseal` per `XKMS_PKCS11_SEAL_STRATEGY`, rooted at
  `pkcs11/token/root-key`.

Handles are ephemeral; state is durable. A restart re-derives handles from state.

## PIN lockout

The PIN budget belongs to the token, not to the process: every process that
opens the same token shares one counter per PIN (`MaxPINAttempts`,
`pkg/pkcs11/module/session.go:1205`) under the dedicated keys
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
  `pkg/pkcs11state/store.go:93`), so the guard holds across hosts.
- **A local file token's guard holds across processes, not only goroutines**
  (#1157). `StorageTypeFile` opens `pkg/storage/file.FileStorage`, whose
  `Put`, `Delete`, `PutIfAbsent`, `CompareAndSwap` and `CompareAndDelete` each
  hold an advisory `flock` on a lock file in the token directory
  (`pkg/storage/file/lock.go`) for the whole guarded read-compare-write.
  Before this, the wrapped engine's atomicity (`pkg/storage/engine.go`'s
  `engineBackend`, still the in-process guarantee this lock is layered over)
  was a process-local mutex: two module instances pointed at the same file
  token directory could interleave their `SpendFailedAttempt` read and write
  and both succeed, undercounting the shared budget. See
  [`../storage-engines/engineering.md`](../storage-engines/engineering.md)
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

## v3.2 status

Four surfaces ship the API and answer `CKR_FUNCTION_NOT_SUPPORTED`:
`module_kem.go` / `module_kem_quantum.go` (KEM), `module_authwrap.go`
(authenticated wrapping), `module_verifysig.go` /
`module_verifysig_quantum.go` (signature-first PQC verification, 9 functions),
`module_async.go` (asynchronous operations). Each has tests asserting the
not-supported answer, so the behaviour is deliberate. Compliance detail:
`docs/pkcs11/module/v32-compliance.md`; changes from v3.0:
`docs/references/pkcs11-v3.0-to-v3.2-changes.md`.

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
