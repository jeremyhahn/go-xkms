- **Password and PIN changes work again under go-qrdb v0.18.0-alpha.** Every
  password-change path was failing with `passphrase strategy is not a software
  strategy`: PKCS#11 token PIN changes (`pkg/pkcs11/localseal`), the xkey GUI
  password change, and barrier `ChangePassword` on every transport. go-qrdb
  v0.18.0-alpha's `ChangePassword` reads the registered strategy's KDF version
  and work factor so a password change preserves a deployment's tuned factor
  rather than silently resetting it to library defaults; xkms registered a
  95-line wrapper struct around go-quicraft's strategy that forwarded every
  method verbatim but **not** `KDFVersion()`/`KDFParams()`, so the parameters
  the re-seal needs were structurally hidden. `pkg/seal.SoftwareStrategy` is now
  a type alias for the canonical go-quicraft strategy re-exported through the
  qrdb SDK, and `NewSoftwareStrategy` re-exports the **deferred** constructor,
  which binds its passphrase at each Seal/Unseal — never the bound one, which
  ignores the credentials handed to unseal and would make wrong-secret unseals
  succeed for the life of the process (go-qrdb#157). xkms contributes only
  hardware seal strategies (TPM2, PKCS#11, cloud KMS); the barrier and seal
  layer belongs to go-qrdb, and a forwarding-only wrapper was just a place for
  the two sides to drift. A wrong passphrase now surfaces as
  `seal.ErrDecryptionFailed` instead of `seal.ErrInvalidCredentials`, which
  remains the sentinel for the hardware path, so the REST barrier/PIN, REST
  tenant and gRPC error mappers gained matching arms: without them a wrong
  password would have degraded from 401 to 500, and that default branch writes
  the raw error, disclosing the crypto library and strategy name to an
  unauthenticated caller. `TestBarrierUnsealHandler_InvalidCredentials` asserted
  only `NotEqual(200)`, which a 500 satisfies, and is tightened to `Equal(401)`
  so the regression cannot recur unseen. Verified: the five previously failing
  tests pass, `pkg/seal` 90.8%, `pkg/api/rest` and `pkg/api/grpc` suites green,
  build and vet clean across all four modules.
