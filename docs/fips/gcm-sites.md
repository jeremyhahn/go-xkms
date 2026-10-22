# AES-GCM sites under `fips140=only`

Under `GODEBUG=fips140=only` the Go Cryptographic Module refuses
`cipher.NewGCM` because it seals with a caller-chosen IV. It allows only GCM
whose nonce is generated inside the module. go-xkms refuses exactly what the
stdlib refuses (owner ruling 116) and keeps no allowlist of its own. This page
lists every GCM site and how each one behaves in that mode (#23).

## Shared helpers

| Helper | What it does |
|---|---|
| `aead.NewGCMForFreshEncrypt` ([random_nonce.go:71](../../pkg/crypto/aead/random_nonce.go#L71)) | Builds a GCM whose nonce comes from the module when the caller supplies none. A caller-supplied nonce under FIPS fails with `aead.ErrArbitraryIVGCMUnavailable` ([random_nonce.go:44](../../pkg/crypto/aead/random_nonce.go#L44)). |
| `aead.SplitGCMWithRandomNonce` / `JoinGCMWithRandomNonce` ([random_nonce.go:142](../../pkg/crypto/aead/random_nonce.go#L142), [:159](../../pkg/crypto/aead/random_nonce.go#L159)) | Split the module's `nonce‖ciphertext‖tag` output into the wire fields, and join them back. |
| `fipstest.OutsideFIPSAfterRefusal` ([fipstest.go:58](../../pkg/testing/fipstest/fipstest.go#L58)) | In the FIPS run, a test asserts the refusal: `errors.Is(err, want)`, or the stdlib's "not allowed in FIPS 140-only mode" text when `want` is nil. It then re-runs itself with `fips140=off` to prove the round trip. |

## Production sites

| Site | Behaviour under `fips140=only` |
|---|---|
| Azure Key Vault symmetric encrypt ([azurekv_symmetric.go:377](../../pkg/backend/azurekv/azurekv_symmetric.go#L377)) | Module nonce. A caller nonce is refused with `ErrArbitraryIVGCMUnavailable`. |
| TPM symmetric encrypt ([symmetric.go:416](../../pkg/tpm2/symmetric.go#L416)) | Same. |
| Symmetric key provider ([backend.go:887](../../pkg/keyprovider/symmetric/backend.go#L887)) | Same. |
| Vault BYOK import ([vault_importexport.go:175](../../pkg/backend/vault/vault_importexport.go#L175)) | Vault's BYOK wrap fixes a zero nonce, so the import is refused with `ErrArbitraryIVGCMUnavailable` before `cipher.NewGCM` runs. |
| xkmsctl FROST dealer packages ([frost_export.go:50](../../cmd/xkmsctl/frost_export.go#L50)) | Sealed as JWE `ECDH-ES+A256KW` / `A256CBC-HS512` (RFC 7518 §4.6.2, §5.2.5). go-jose builds `A*GCM` with `cipher.NewGCM`, so a GCM content algorithm would be refused. A package sealed as `A256GCM` no longer imports, so re-export it. `TestFrostPackageExport_GoldenFixture` pins the format. |

Every JWE `A*GCM` content encryption goes through go-jose and is refused under
FIPS. `pkg/encoding/jwe` callers that need FIPS use `A256CBC-HS512`.

## Related refusals

These are not GCM, but they come up in the same suite.

- **X25519 (Noise NK).** Refused by the module. go-truststrap reports it as
  `bootstrap.ErrNoiseFIPSUnsupported`. The Noise tests in
  `pkg/trust/bootstrap`, `pkg/pairingproto`, `pkg/trust/clusterca` and
  `cmd/xkmsctl` assert that refusal, then the round trip outside FIPS.
- **HKDF secrets under 112 bits.** The personal vault derives keys with stdlib
  `crypto/hkdf` ([vault.go:573](../../pkg/staticpw/vault.go#L573)). That
  returns the refusal as a `*VaultCryptoError`, where `x/crypto/hkdf`
  panicked. Real factor secrets are 160 bits or more.

## Not covered here

- `pkg/testing/pkcs11test` (oracle and mock) and `pkg/pkcs11`: see
  [README.md](README.md).
- The xkey module, including `xkey/pkg/nativemsg/crypto.go`: see [xkey.md](xkey.md).
- `pkg/acme`.
- SHA-1 refusals inside go-qrdb.
