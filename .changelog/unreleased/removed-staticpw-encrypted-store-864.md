- **Removed `pkg/staticpw.EncryptedStore`, `PINAccessStore`, and
  `SessionStore` (BREAKING for any direct import of these types).** They
  were complete and tested but constructed nowhere outside their own tests
  (#864): xkmsd's `PasswordServicer` (`pkg/xkms/servicer_password.go`) gets
  its confidentiality from the barrier wrapping `staticpw.Store`/`ScopedStore`
  and implements session unlock/lock via
  `TenantPasswordStoreManager.UnlockTenant`/`LockTenant` against the qrdb
  tenant barrier, not via `SessionStore`; xkey's local `staticpw.Store` is
  unwrapped (same barrier-or-plain-file pattern as OATH/FIDO2), and `xkey
  password unlock`/`lock`/`access-mode` are pure RPC calls to xkmsd's
  `sdk/go/transport.PasswordService` — xkey never had a local encrypted or
  PIN-gated store to begin with. `staticpw.AccessMode` and its
  `AccessPINPerOperation`/`AccessSessionBased` constants are unchanged and
  still describe the vocabulary `PasswordStoreSetAccessMode` validates
  against, but only `AccessSessionBased` is reachable: the mode `PINAccessStore`
  implemented can never become the servicer's effective mode. Also removed:
  the now-unproducible `staticpw.ErrNilEncrypter`,
  `ErrNilInnerStore`, `ErrNilPINManager`, `ErrPINRequired`,
  `ErrEncryptFailed`, `ErrDecryptFailed`, `ErrPasswordNotEncrypted`,
  `ErrCryptoEncryptFailed`, and `ErrCryptoDecryptFailed` sentinels (the last
  two were already unreferenced before this change), and the two dead
  `ErrNilEncrypter` mappings in `pkg/api/grpc/service_password.go`.
