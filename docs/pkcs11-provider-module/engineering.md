# PKCS#11 Provider Module — Engineering Contract

> **Status: NORMATIVE** · Feature: `pkcs11-provider-module` · Repo: `go-xkms` · Last verified: 2026-08-19

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
- **Session and object handles are per-process.** They are not portable across
  processes even in remote mode, where the *state* is shared but the handles are
  not.
- **Concurrency.** Cryptoki permits concurrent sessions; the module serialises
  where the backend requires it and relies on CAS for shared state.

## Error semantics

`pkg/pkcs11/module/errors.go` maps Go errors to `CK_RV` values and back:
`NewPKCS11ErrorWithMessage(rv, msg)`, `NewPKCS11ErrorFull(...)`,
`backendCKRV(err, fallback)`. Every `CKR_*` constant has a string form and a Go
sentinel — `CKR_FUNCTION_NOT_SUPPORTED` (`0x00000054`) ↔ `ErrFunctionNotSupported`.

**Fail-closed paths:** `C_Initialize` with an unreachable or uncompiled backend;
any operation before `C_Login` where the mechanism requires it; a CAS conflict
on token state; an unusable offline key directory.

## Persistence

- **Remote mode** — token and object state through `pkg/pkcs11state.Store` over
  the `PKCS11State*` RPCs, into go-qrdb.
- **Offline mode** — key material under `XKMS_PKCS11_LOCAL_KEYDIR`, protected by
  `pkg/pkcs11/localseal` per `XKMS_PKCS11_SEAL_STRATEGY`, rooted at
  `pkcs11/token/root-key`.

Handles are ephemeral; state is durable. A restart re-derives handles from state.

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
  `module_verifysig_*_test.go`, `module_async_test.go`).
- **Integration** — `test/integration/pkcs11`, driving real consumers.
- **Compatibility** — the two-call convention and mechanism-parameter
  marshalling are the fragile CGO seams and have dedicated suites.

## Observability

The module logs into the consumer's process, which is a constraint rather than a
choice — it cannot assume a log destination. Failures surface as `CK_RV` values,
so `CKR_*` codes are the primary diagnostic; keep the string mapping in
`errors.go` complete, because a bare hex code in a consumer's log is otherwise
unreadable.
