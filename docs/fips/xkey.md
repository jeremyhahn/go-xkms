# The xkey module under `fips140=only`

Under `GODEBUG=fips140=only` the Go Cryptographic Module refuses X25519, SHA-1
HMAC, HMAC keys under 112 bits and GCM over a caller-chosen IV. xkey refuses
exactly what the stdlib refuses (owner ruling 116) and keeps no allowlist of its
own. This page lists each xkey site that meets one of these refusals and how it
behaves in that mode (#23). The root-module GCM sites are in
[gcm-sites.md](gcm-sites.md).

## Production sites

| Site | Behaviour under `fips140=only` |
|---|---|
| OATH SHA-1 and short-key gate ([fips.go:23](../../xkey/pkg/oath/fips.go#L23)) | Keys on `crypto/fips140.Enforced`, the flag `crypto/hmac` checks. SHA-1 HOTP/TOTP and secrets under 112 bits are refused with a typed error; under `fips140=on` they still work, as they do in the stdlib. |
| Browser-extension session keys ([crypto.go:75](../../xkey/pkg/nativemsg/crypto.go#L75)) | X25519 is refused. `NewSessionCrypto` returns `ErrHandshakeFailed` wrapping the stdlib's refusal, so the handshake failure says why. |
| Phone TCP pairing server ([tcp_server.go:252](../../xkey/pkg/phone/tcp_server.go#L252)) | A generated Noise static key is X25519 and is refused. `NewTCPPairingServer` returns `ErrTCPServerStartFailed` wrapping the stdlib's refusal. |
| Phone backend, pairing, attestation and e2eprobe Noise sessions | The Noise static key is X25519. Session setup fails with `bootstrap.ErrNoiseFIPSUnsupported`. |
| GUI phone service pairing and connect ([phone_service.go:687](../../xkey/pkg/gui/services/phone_service.go#L687)) | `Pair` and `Connect` join their typed error (`ErrPhonePairFailed`, `ErrPhoneMissingKeys`, `ErrPhoneConnectFailed`) with the cause, so `bootstrap.ErrNoiseFIPSUnsupported` reaches the caller. |
| GUI certificate fingerprints ([tpm_service.go:3162](../../xkey/pkg/gui/services/tpm_service.go#L3162)) | `ParseCertificate` leaves the SHA-1 and MD5 fingerprints empty, since the module refuses both digests. The SHA-256 fingerprint is unchanged. |

## Tests

Each test that runs one of these primitives asserts the refusal under
`fips140=only` with `fipstest.OutsideFIPSAfterRefusal`
([fipstest.go:58](../../pkg/testing/fipstest/fipstest.go#L58)), then re-runs
itself under `fips140=off` to prove the round trip. The per-package helper is a
`fips_test.go`: `noiseOutsideFIPS` in `xkey/pkg/phone`, `xkey/pkg/pairing` and
`xkey/pkg/attestation/attesttest`, `x25519OutsideFIPS` in
`xkey/pkg/nativemsg`, and `noiseOutsideFIPS`, `serviceNoiseOutsideFIPS`,
`nssdbOutsideFIPS` and `nativeMessagingOutsideFIPS` in
`xkey/pkg/gui/services`.

- **`xkey/test/e2esupport/sshechod`.** x/crypto/ssh's default key exchange is
  curve25519, so `sshClient` asserts the refusal of the handshake. The test
  pins no algorithm list.
- **`xkey/pkg/pkcs11` embedded transport.** A ciphertext sealed under FIPS
  carries `GCMNonceMode: "random"`. The round-trip test echoes it back on the
  `DecryptRequest`, as every caller must, and passes in both modes.
- **`xkey/pkg/gui/services`.** The PKCS#11 IPC round trip echoes
  `GCMNonceMode` the same way; the caller-nonce and tag-size tests assert
  `pkcs11svc.ErrEncryptionFailed`, the error that crosses the socket. The
  secure-browser tests assert `nssdb.ErrFIPSUnsupported`, since cert9.db and
  key4.db mandate SHA-1. Certificate tests check the legacy fingerprints with
  `assertLegacyFingerprints`. The password-backup header test expects the KDF
  of `xkms.NewFIPSAwareHasher`: PBKDF2-SHA256 under FIPS, Argon2id otherwise.
  OATH fixtures use HMAC-SHA-256.
- **`xkey/pkg/gui`.** The inventory tests seed an HMAC-SHA-256 OATH credential.
- **`xkey/cmd/xkey/cmd` device relay.** `xkey device relay` loads the paired
  device's local Noise static key, which is X25519, so `runDeviceRelay`
  returns its `WrappedError` around `bootstrap.ErrNoiseFIPSUnsupported`. The
  relay tests assert that refusal with `relayOutsideFIPS`. The device-resolution
  tests run no X25519: their paired-device keys are random 32-byte fixtures,
  since `resolveListenTargetDevice` only decodes them.
- **`xkey/cmd/xkey/cmd` OATH multi-backend tests.** They add their credentials
  with SHA-256 instead of the SHA-1 default, because they test backend routing,
  not the hash. The SHA-1 refusal itself is tested in `xkey/pkg/oath`.

## Not covered here

- `TestPKCS11V3Suite` in `xkey/pkg/pkcs11` runs the shared root suite
  (`sdk/go/xkmstest`, the root `pkg/pkcs11/module` and its mock client). It
  fails the same way as `pkg/pkcs11/module`'s own copy, so the fix belongs to
  the root module.
- The five `TestSSHConsoleE2E_*` tests in `xkey/pkg/gui/services` fail in the
  root `pkg/ssh/console`: the RFC 6455 accept key is SHA-1.
- `xkey/pkg/serverid/serveridtest`.
