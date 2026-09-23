- **`pkg/crypto/mem`'s hand-rolled `GuardedBuffer` is retired; every caller
  moves to go-enclave's `MemoryEnclave` — BREAKING.** `GuardedBuffer`'s Linux
  mlock call discarded its own error (`_ = sysCallMlock(dataRegion)`) and
  proceeded unlocked with no signal when the kernel refused — key material
  then sat on swappable pages silently. go-enclave's constructors return
  `ErrLockedMemoryUnavailable` for the same failure instead of failing open,
  and it was already a direct dependency of this module
  (`pkg/storage/sealed`), so this removes a parallel implementation rather
  than adding one. `pkg/crypto/mem` is deleted outright (no deprecation
  period, no shim — this project carries no backward compatibility).
  `mem.Zero`/`mem.GuardedBuffer` callers move to `enclave.Wipe` /
  `enclave.MemoryEnclave`: `pkg/crypto/kdf/hasher.go`,
  `pkg/keyprovider/pkcs8/sealer.go`, `pkg/server/credentials/service.go`,
  and `pkg/pintpm2/backend.go`, whose FIDO2 PIN hash cache
  (`fido2Guard atomic.Pointer[mem.GuardedBuffer]`) is now
  `fido2Enclave atomic.Pointer[enclave.MemoryEnclave]`, with hash comparison
  via `MemoryEnclave.EqualTo` (constant-time, fail-closed on a nil or
  destroyed enclave) replacing a direct `subtle.ConstantTimeCompare` over
  `Bytes()`. The SDK re-export `sdk/go/crypto.go` keeps `SecureMemZero` as a
  drop-in `enclave.Wipe` alias (an existing go-quicbaas caller depends on the
  exact signature) and drops the `GuardedBuffer`-only re-exports
  (`SecureMemGuardedBuffer`, `SecureMemNewGuardedBuffer`,
  `SecureMemZeroAndFree`, and their error types), since go-enclave is
  already a public dependency SDK consumers can import directly. The three
  remaining hand-rolled zero-loops flagged alongside this
  (`pkg/pkcs11/module`'s `zeroize`, and xkey's `luks.clearBytes` /
  `authenticator.clearBytes`) are also retired in favor of `enclave.Wipe`;
  `authenticator.clearBytes` was package-shared beyond the one call site
  named in the issue, so every call site in `xkey/pkg/authenticator`
  (`attestation.go`, `key_wrapper.go`, `key_manager.go`, `token.go`,
  `ext_hmac_secret.go`) moves with it. `cmd/xkmsd` now also calls
  `enclave.WipeAll()` in its orderly-shutdown defer, alongside the existing
  `secure.Purge()` (go-qrdb#'s memguard-backed `Secret`/`Buffer` remain a
  second, still-necessary protected-memory subsystem pending qrdb's own
  migration to go-enclave); libraries in this repository call neither.
  Deferred to follow-on issues, both blocked on upstream releases that have
  not shipped: moving `cmd/xkmsctl`'s and `pkg/server/bootstrap_suite.go`'s
  direct `*memguard.LockedBuffer` use onto go-truststrap's `MemoryEnclave`
  API once that wave lands (go-truststrap#60), and dropping
  `github.com/awnumar/memguard` from `go.mod` once go-qrdb's own `pkg/secure`
  delegates to go-enclave. go-xkms#623.
