- **BREAKING: `BackupKey.PrivateKey`, `StoredCredential.PrivateKey` (in both
  `xkey/pkg/authenticator` and `xkey/pkg/cdp`), `OATHCredentialInfo.Secret`
  and `PasswordInfo.Password` are no longer plaintext exported fields — the
  key/secret/password material now lives in mlocked, guard-paged protected
  memory (`*secure.Buffer`) and is reached only through `SetXxx`/`XxxBytes`
  or `SetXxx`/`XxxString` accessors, closing the last of the go-xkms#549
  secure-analyzer findings for `pkg/backup`, `xkey/pkg/authenticator`,
  `xkey/pkg/cdp` and `xkey/pkg/backup`.** Every type keeps its historical
  JSON shape — `BackupKey`, `StoredCredential` (both packages),
  `OATHCredentialInfo` and `PasswordInfo` all gained a custom
  `MarshalJSON`/`UnmarshalJSON` pair (matching the `xkey/pkg/oath.Credential`
  pattern) that serializes the protected value under the same historical
  JSON key it always used, so archives and credential stores written by a
  prior build keep decoding byte-for-byte — proven by a golden-fixture test
  per type. `cdp.StoredCredential`'s `MarshalJSON` uses a value receiver
  (not pointer) because that type's public API passes it by value
  throughout the package; a pointer-receiver `Marshaler` would be silently
  skipped by `encoding/json` for a non-addressable value and drop the
  protected field with no error. Every caller across `pkg/backup`,
  `xkey/pkg/authenticator`, `xkey/pkg/cdp`, `xkey/pkg/backup`,
  `xkey/pkg/sync` and `xkey/cmd/xkey/cmd` was converted to the new setters
  and accessors, including `MemoryStorage.copyCredential` (now
  error-returning, since cloning a protected buffer can fail) and the
  CDP-capture/sync path in `xkey/cmd/xkey/cmd/fido2.go`. The five
  corresponding `scripts/secure-analyzer-allowlist.txt` `pre-existing`
  entries are removed.
