- **BREAKING: PKCS#11/PIV token PINs are now `*secure.Secret` instead of
  plain Go strings across the RNG, PIV certificate storage, PKCS#11 mTLS,
  and SDK PIV-signing surfaces.** `rand.PKCS11Config.PIN`
  (`pkg/crypto/rand/rand.go`), `pivcert.PKCS11StorageConfig.PIN` and
  `.SOPIN` (`pkg/pivcert/pivcert.go`), `auth.PKCS11TLSConfig.PIN`
  (`pkg/auth/pkcs11_tls.go`), `xkms.PIVCryptoSigner.PIN`
  (`sdk/go/piv_signer.go`), and `xkmsctl`'s `Config.PKCS11PIN`
  (`cmd/xkmsctl/config.go`) all change from `string` to `*secure.Secret`, so
  a configured PIN no longer sits in memory as an unwipeable Go string for
  the life of the process. A nil PIN replaces the previous empty-string
  sentinel; every `x.PIN != ""`/`== ""` check became a nil check. Each PIN is
  opened only immediately around the boundary call that requires a plain
  string — miekg/pkcs11's `Login`, the in-house `pkcs11module.Config`, and
  `PIVSignRequest`'s wire transport — and the opened buffer is destroyed
  right after. `xkmsctl`'s `--pkcs11-pin` flag and xkey's PIV PKCS#11
  wiring now seal their raw flag/config strings into a `*secure.Secret`
  before handing them to these APIs. Updated every call site in the root
  module, `sdk/go`, and `xkey` (`pkg/crypto/rand/pkcs11.go`,
  `pkg/pivcert/pkcs11/pkcs11.go`, `cmd/xkmsctl/root.go`, `admin.go`,
  `xkey/cmd/xkey/cmd/piv_pkcs11.go`, and the corresponding test fixtures).
  Removed the four now-satisfied `pre-existing` rule-3 allowlist lines from
  `scripts/secure-analyzer-allowlist.txt` for these fields.
