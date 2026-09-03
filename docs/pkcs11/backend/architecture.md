# Architecture

## Position in the stack

```
xkms service / transports (rest, grpc, quic, mcp, unix)
        |  keyProviders["pkcs11"]
        v
pkg/backend/pkcs11.Backend          <- this package
        |  SessionPool (channel of CK_SESSION_HANDLE)
        v
github.com/miekg/pkcs11 (cgo)
        v
vendor Cryptoki library (.so)  ->  HSM / token
```

The backend is registered by `pkg/server/backend_pkcs11.go` under the key
`"pkcs11"`, exactly like the other backends (`software`, `tpm2`, `awskms`,
`gcpkms`, `azurekv`, `vault`, `phone`). It satisfies the same `types.KeyProvider`
contract, so nothing above it knows it is talking to an HSM.

## The Backend type

```go
type Backend struct {
	config        *Config
	p11ctx        *pkcs11.Ctx
	pool          *SessionPool
	ownsP11ctx    bool // tracks if this backend owns the PKCS#11 context (should Finalize/Destroy)
	tracker       types.AEADSafetyTracker
	supportsMLDSA bool              // dynamically detected ML-DSA mechanism support
	supportsMLKEM bool              // dynamically detected ML-KEM mechanism support
	slotModel     pivcert.SlotModel // nil for generic (non-PIV) tokens
	mu            sync.RWMutex
	types.KeyProvider
}
```

Interfaces asserted at compile time in the package:

| Interface | File |
|---|---|
| `backend.ImportExportBackend` | `pkcs11_importexport.go:39` |
| `types.SymmetricKeyProvider`, `types.SymmetricKeyProviderWithTracking` | `pkcs11_symmetric.go:697` |
| `types.SymmetricKey`, `types.SymmetricEncrypter` | `pkcs11_symmetric.go:699` |
| `types.KeyAgreementProvider` | `pkcs11_ecdh.go:501` |
| `types.Sealer` | `sealer.go:29` |

`Capabilities()` reports `types.NewHardwareCapabilities()` (Keys, Signing,
Decryption, `HardwareBacked=true`, `KeyRotation=false`,
`SecurityLevel=High`) plus `SymmetricEncryption`, `Import`, `Export`, and the
two post-quantum flags that `probeQuantumMechanisms` sets from the token's
actual `C_GetMechanismList` output.

## Lifecycle

1. `NewBackend(config)` — validates config only. No library is loaded, no
   session opened. A bad path or missing storage fails here.
2. `Initialize(soPIN, userPIN)` — **operator action**, first-time token setup.
   Runs `C_InitToken` + `C_InitPIN` in a throwaway context, then logs in.
   Returns `ErrAlreadyInitialized` when the token is already initialized.
3. `Login()` — the boot path. Loads the library, `C_Initialize`s it, resolves
   the slot, builds the session pool, attaches the PIV slot model for
   `libykcs11`, and probes ML-DSA/ML-KEM support.
4. Operations.
5. `Close()` — closes the pool, then `C_Finalize` + `Destroy` **only if this
   backend created the context** (`ownsP11ctx`). Idempotent.

`pkg/server/backend_pkcs11.go` deliberately calls `Login()` and not
`Initialize()` at daemon start:

```go
	// Establish the session pool against the (pre-initialized) token. Without
	// this the backend constructs but every operation fails with
	// ErrNotInitialized. Token SO-initialization is an operator action
	// (softhsm2-util / HSM tooling), NOT a boot action -- Login only
	// authenticates with the configured user PIN.
	if err := pkcs11Backend.Login(); err != nil {
		return &ErrBackendCreate{Backend: "PKCS#11", Err: err}
	}
```

## Slot resolution

`resolveSlot()` (`pkcs11.go:640`) applies, in order:

1. `Config.Slot` if set — used verbatim.
2. `Config.TokenLabel` — matched against `C_GetTokenInfo().Label` with trailing
   spaces trimmed (Cryptoki pads labels to 32 bytes).
3. Otherwise the first slot with a token present.

Every operation that opens its own session (`ImportKey`, `ExportKey`,
`ExportKeyMaterial`, symmetric encrypt/decrypt) calls `resolveSlot()` rather
than taking `slots[0]`; on a multi-token host the first slot is not necessarily
the configured one, and picking it would authenticate with the wrong PIN.

## Session pool

`SessionPool` (`session_pool.go`) is a buffered channel of pre-opened R/W
sessions — a lock-free semaphore, not a mutex-guarded free list. Default size
is `DefaultSessionPoolSize = 8`, overridable via `Config.SessionPoolSize`.

Construction opens `size` sessions on the slot and logs in **once**: Cryptoki
login state is per token, not per session, so one `C_Login` covers the whole
pool. `CKR_USER_ALREADY_LOGGED_IN` is treated as success because the manager or
another pool on the same token may have logged in first.

### Checkout

```go
func (p *SessionPool) WithSession(fn func(session pkcs11.SessionHandle) error) error
```

Rules for callers:

- **The session handle must not escape `fn`.** It is returned to the pool the
  moment `fn` returns, and another goroutine may be using it immediately after.
- Do not start an operation inside `fn` and finish it in a later `WithSession`.
  Cryptoki allows at most one search / one active crypto operation per session;
  a leaked `C_FindObjectsInit` makes every later search on that session fail with
  `CKR_OPERATION_ACTIVE`. `findOneObject` (`pkcs11_importexport.go:761`) exists
  precisely to run a complete init/find/final cycle every time.
- Do not call `Close()` from inside `fn`.

### The `done` channel

`Close()` sets an atomic `closed` flag, closes `done`, then drains and closes
every pooled session. The `done` channel is not redundant with the flag:

```go
	// done is closed by Close to release any caller already blocked waiting for
	// a session. The closed flag alone cannot do that: a caller checks it,
	// passes, and may then be preempted before its receive on pool, by which
	// time Close has drained the channel and nothing will ever be sent again.
	// That goroutine would block forever -- a leak on every shutdown that races
	// in-flight work, which is exactly when shutdown happens.
	done chan struct{}
```

`WithSession` therefore selects on both `p.pool` and `p.done`. A caller holding
a session when `Close` lands closes that session directly instead of returning
it to a drained pool. `Close` is idempotent (`CompareAndSwap`) and tolerates a
zero-value pool (nil `done` is not closed).

### SO elevation

`WithSOSession(soPin, userPin, fn)` logs out, logs in as `CKU_SO`, runs `fn`,
then restores the `CKU_USER` login. YubiKey PIV requires this for key
generation and object destruction. Because login state is per token, the
caller **must** hold the backend write lock for the whole call — otherwise a
concurrent operation observes the intermediate SO state.

## Key addressing

One identifier is used for both `CKA_LABEL` and `CKA_ID` on every object the
backend creates:

```go
func createKeyID(attrs *types.KeyAttributes) string {
	if attrs.KeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		return fmt.Sprintf("%s.", attrs.CN)
	}
	return fmt.Sprintf("%s.%s", attrs.CN, strings.ToLower(attrs.KeyAlgorithm.String()))
}
```

`keyIDToCN` is its exact inverse and is what `ListKeys` uses to recover the CN,
so enumerated attributes resolve back to the `CKA_ID` they were read from.

`resolveKeyID` (`pkcs11.go:1427`) overrides this for PIV:

1. `KeyAttributes.PIVSlot` (highest priority) → single-byte `CKA_ID` via
   `pivpkcs11.PIVSlotToCKAID`.
2. `Config.Slot` when the library is `libykcs11` → `createSlotID(slot)`.
3. Otherwise `createKeyID(attrs)`.

Import uses the same identifier and verifies it afterwards
(`verifyImportedKeyIdentity`), repairing `CKA_LABEL`/`CKA_ID` with
`C_SetAttributeValue` if the token dropped them from the unwrap template, and
destroying the object if it cannot — an unaddressable key object is orphaned
key material.

## CKA_EC_POINT encodings

PKCS#11 v3.2 §6.3.3 Table 64 defines a short-Weierstrass `CKA_EC_POINT` as the
DER encoding of an OCTET STRING wrapping the X9.62 uncompressed point, but
tokens in the field disagree: some store the wrapper, others store the bare
point. `exportECDSAPublicKey` accepts both.

The two forms cannot be told apart by their leading byte — `0x04` is both the
OCTET STRING tag and the uncompressed-point marker — so `decodeECPoint`
discriminates on length, which is exact rather than probabilistic. For a curve
over a `byteLen`-byte field the bare point is always `1 + 2*byteLen` bytes (65
on P-256, 97 on P-384, 133 on P-521), and any DER OCTET STRING wrapping it adds
at least a tag and a length octet, so the wrapped form is strictly longer. The
curve comes from `CKA_EC_PARAMS`, which is all the information the decision
needs.

An attribute value that is neither form — the wrong size, trailing bytes after
the OCTET STRING, or an OCTET STRING wrapping the wrong number of bytes — is
reported as `ErrInvalidKeyAttributes` rather than guessed at. A public key
assembled from misread bytes would verify nothing, and the failure would
surface far from its cause.

## YubiKey PIV specialisation

`Config.IsYubiKeyPIV()` (library path contains `ykcs11`) switches several paths:

- Minimal key templates. `libykcs11` sets `CKA_TOKEN`, `CKA_SIGN`, `CKA_VERIFY`,
  `CKA_PRIVATE`, `CKA_SENSITIVE` itself per slot; supplying them returns
  `CKR_ATTRIBUTE_VALUE_INVALID` (`buildYubiKeyRSATemplates`,
  `buildYubiKeyECDSATemplates`).
- Key generation runs under `WithSOSession` with the management key; without a
  configured SO PIN the call fails with `ErrSOPINRequired`.
- Certificate deletion goes through `hardware.NewPKCS11CertStorageWithSO`,
  because `libykcs11` rejects `C_DestroyObject` under `CKU_USER` with
  `CKR_USER_TYPE_INVALID`.
- Ed25519 is rejected outright with a pointer to ECDSA P-256 or RSA.

## Thread safety

`Backend.mu` is an `sync.RWMutex`; mutating operations (generate, import,
initialize, close) take the write lock, lookups take the read lock. `Seal` and
`Unseal` deliberately do **not** hold the lock across their call into
`SymmetricEncrypter`, which re-acquires it — `checkInitialized` takes and
releases the read lock itself to avoid the recursive-read-lock deadlock that
`sync.RWMutex` documents when a writer arrives between the two acquisitions.
