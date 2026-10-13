# Advanced Cryptography Guide

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: the ECIES and ECDH helper packages `pkg/crypto/ecies` and `pkg/crypto/ecdh`, which are Go library APIs with no server or CLI surface of their own.

This guide covers public-key encryption with ECIES, key agreement with ECDH,
and HKDF key derivation. For ECDH with a key held in a backend, use the server
operation `POST /api/v1/keys/derive-ecdh` or `xkmsctl key derive-ecdh` (see
[API parity](api-parity.md)). This page covers the in-process helpers.

## ECIES

`pkg/crypto/ecies` encrypts a message to the holder of an ECDSA key on P-256,
P-384 or P-521. `Encrypt` (`pkg/crypto/ecies/ecies.go:111`):

1. Generates an ephemeral key pair on the recipient's curve.
2. Runs ECDH between the ephemeral private key and the recipient's public key.
3. Derives a 32-byte key from the shared secret with HKDF-SHA256, using no
   salt and the info string `ecies-encryption` (`ecies.go:135`).
4. Encrypts with AES-256-GCM.

The GCM tag provides the message authentication; there is no separate MAC.
`Decrypt` (`ecies.go:197`) reverses these steps.

### Ciphertext format

```
ephemeral public key (uncompressed) || nonce (12) || tag (16) || ciphertext
```

| Curve | Public key | Tag starts at | Ciphertext starts at | Overhead |
|-------|-----------|---------------|----------------------|----------|
| P-256 | 65 bytes | 77 | 93 | 93 bytes |
| P-384 | 97 bytes | 109 | 125 | 125 bytes |
| P-521 | 133 bytes | 145 | 161 | 161 bytes |

The ciphertext is as long as the plaintext.

### Usage

```go
import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"

    "github.com/jeremyhahn/go-xkms/pkg/crypto/ecies"
)

recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil {
    return err
}

ciphertext, err := ecies.Encrypt(rand.Reader, &recipient.PublicKey, []byte("secret"), nil)
if err != nil {
    return err
}

plaintext, err := ecies.Decrypt(recipient, ciphertext, nil)
if err != nil {
    return err
}
```

The `random` argument must not be nil, but it is never read. The ephemeral
key comes from `crypto/rand`, and the GCM nonce is generated inside the FIPS
140-3 module boundary (`cipher.NewGCMWithRandomNonce`, `ecies.go:89`). So two
encryptions of the same plaintext always produce different ciphertexts.

A nil plaintext is rejected. An empty slice is valid.

### Additional authenticated data

The last argument is optional additional authenticated data (AAD). It is
authenticated but not encrypted, and `Decrypt` fails unless it gets the same
value:

```go
aad := []byte("user-id:" + userID)
ciphertext, err := ecies.Encrypt(rand.Reader, pub, data, aad)
// ...
plaintext, err := ecies.Decrypt(priv, ciphertext, aad)
```

### Errors

The errors are messages, not sentinels:

- `random source cannot be nil`
- `public key cannot be nil` / `private key cannot be nil`
- `plaintext cannot be nil` / `ciphertext cannot be nil`
- `ciphertext too short: …`
- `decryption failed (authentication error)`, returned for a wrong key, a
  wrong AAD, or a modified ciphertext

Treat any `Decrypt` error as a failed decryption. Don't show its detail to
end users.

### Security properties

- **Provided:** confidentiality and integrity through AES-256-GCM, and a fresh
  ephemeral key and nonce for each message.
- **Not provided:**
  - Sender authentication: anyone with the public key can encrypt. Sign the
    message if the recipient must know who sent it.
  - Forward secrecy against the recipient: whoever holds the recipient's
    private key can decrypt every message ever sent to it.
  - Replay protection.
  - Post-quantum security.

### Large data

`Encrypt` works on one in-memory buffer. For large payloads, encrypt the data
under a random AES-256 key and use ECIES to encrypt only that 32-byte key:

```go
dataKey := make([]byte, 32)
if _, err := rand.Read(dataKey); err != nil {
    return err
}
wrappedKey, err := ecies.Encrypt(rand.Reader, recipientPub, dataKey, nil)
// Encrypt the payload with AES-256-GCM under dataKey (crypto/cipher),
// then send wrappedKey alongside the encrypted payload.
```

### Performance

The package has benchmarks for each curve, with and without AAD
(`pkg/crypto/ecies/ecies_test.go:1004`):

```bash
go test -run '^$' -bench . ./pkg/crypto/ecies
```

## ECDH

`pkg/crypto/ecdh` wraps the Go standard library's `crypto/ecdh` for ECDSA keys:

- `DeriveSharedSecret(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey)`
  (`pkg/crypto/ecdh/ecdh.go:56`) returns the raw shared secret. Both keys must
  be on the same curve: P-256, P-384 or P-521.
- `DeriveKey(sharedSecret, salt, info []byte, keyLength int)` (`ecdh.go:105`)
  runs HKDF-SHA256 on the secret. The salt may be nil.

Don't use the raw secret as a key. Derive one with `DeriveKey`, and use a
different `info` string for each key, so each purpose gets an independent
key from the same secret:

```go
import "github.com/jeremyhahn/go-xkms/pkg/crypto/ecdh"

secret, err := ecdh.DeriveSharedSecret(alicePriv, bobPub)
if err != nil {
    return err
}
encKey, err := ecdh.DeriveKey(secret, nil, []byte("encryption"), 32)
if err != nil {
    return err
}
macKey, err := ecdh.DeriveKey(secret, nil, []byte("authentication"), 32)
```

For X25519 key agreement, see the
[x25519-ecdh example](../../../examples/advanced/x25519-ecdh/).

## Choosing a scheme

| Task | Use |
|------|-----|
| Encrypt a short message to one EC key holder | ECIES |
| Encrypt large data to one recipient | AES-256-GCM, with the data key encrypted by ECIES |
| Encrypt to an RSA key | RSA-OAEP: `POST /keys/{id}/encrypt-asym` or `xkmsctl key encrypt-asym` |
| Establish a shared key between two parties | ECDH, then `DeriveKey` |
| Encrypt with a key the server holds | `POST /keys/{id}/encrypt` or `xkmsctl key encrypt` |
| Prove who sent a message | Sign it; ECIES does not authenticate the sender |

## See Also

- [ECIES examples](../../../examples/advanced/ecies/README.md): basic use, and use with a backend-held key
- [Crypto backends](../../../docs/crypto-backends/user.md)
- [Key import and export](key-import-export.md)
