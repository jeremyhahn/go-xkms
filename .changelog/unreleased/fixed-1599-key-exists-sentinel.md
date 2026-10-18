- **A CA that loses a concurrent key-generate race now gets the winner's key on
  every backend.** `getOrGenerateKey` (`pkg/ca/csr.go`) recovers only on
  `errors.Is(err, backend.ErrKeyAlreadyExists)`, but most backends reported
  "already exists" with their own sentinel, so the losing caller failed. The
  awskms, azurekv, gcpkms, pkcs8 and frost `ErrKeyAlreadyExists`, phone's
  `ErrKeyExists` and the keystore's `xkms.ErrKeyAlreadyExists` are now
  `backend.ErrKeyAlreadyExists` itself. `xkms.KeyExistsError` unwraps to it.
  The awskms and azurekv `Save` report an existing key with it, not
  `backend.ErrFileAlreadyExists`. gcpkms maps Cloud KMS's gRPC `AlreadyExists`
  from `CreateCryptoKey` to it (#1599).
