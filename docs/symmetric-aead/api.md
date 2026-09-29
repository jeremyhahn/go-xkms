# Symmetric Encryption & AEAD — API

> **Status: NORMATIVE** · Feature: `symmetric-aead` · Repo: `go-xkms` · Last verified: 2026-09-28

Transport shapes are described once in
[`../key-management/api.md`](../key-management/api.md) §"How the six
transports are shaped". This document covers the fields and modes specific to
symmetric AEAD encryption.

## Capability matrix

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Generate symmetric key | `POST /api/v1/keys` (`Algorithm` = an AES-GCM size or `"symmetric"`, or `chacha20-poly1305`/`xchacha20-poly1305`) | same request shape | same | same | `Backend.GenerateSymmetricKey` |
| Encrypt | `POST /api/v1/keys/{id}/encrypt` | same request shape | same | same | `SymmetricEncrypter.Encrypt` |
| Decrypt | `POST /api/v1/keys/{id}/decrypt` | same request shape | same | same | `SymmetricEncrypter.Decrypt` |
| Rotate | `POST /api/v1/keys/{id}/rotate` (generic; resets AEAD tracking) | same | same | same | `Backend.RotateKey` |
| Key derivation (`C_DeriveKey`-equivalent) | see [`../key-management/api.md`](../key-management/api.md) | same | same | same | `Backend.DeriveFromSymmetricKey` |

## `POST /api/v1/keys/{id}/encrypt`

Request (`pkg/api/rest/types.go:159-181`, `EncryptRequest`):

```json
{
  "plaintext": "<base64>",
  "additional_data": "<base64, optional>",
  "nonce": "<base64, optional — server generates one if omitted>",
  "mode": "\"\" (default AEAD) | \"cbc\" | \"cbc-pad\"",
  "iv": "<base64, CBC modes only>",
  "tag_size": 0
}
```

`tag_size` is the AEAD tag length in bytes (0 selects the cipher's
full-length tag; AES-GCM admits 12-16 bytes per NIST SP 800-38D §5.2.1.2).

`nonce` may be used once per key per server process. A second encryption
under the same key and nonce is refused, including a nonce the server
generated for an earlier response and a nonce used by an AES-GCM wrap under
that key. The error wraps `aead.ErrNonceReuse` and is reported as `409
Conflict` (gRPC `AlreadyExists`, the MCP JSON-RPC duplicate code) through the
shared `apierrors.AEADSentinelClasses` table (`pkg/api/apierrors/tables.go`)
every transport's `mapKeyOpError` consults (go-xkms#1223); it used to fall
through to the catch-all `500`. A bounded nonce tracker that has reached
capacity wraps `aead.ErrNonceTrackerFull` and is reported as `503 Service
Unavailable` (gRPC `ResourceExhausted`) through the same table. Leave `nonce`
empty unless a protocol requires it. See [`architecture.md`](architecture.md)
§"Caller-supplied nonces" for the limits: the record does not survive a
restart and is not shared between cluster nodes.

A caller-supplied `nonce` against AWS KMS, GCP KMS, Vault Transit or a paired
phone's symmetric backend is refused outright with
`backend.ErrCallerNonceNotSupported` (`400 Bad Request` / `InvalidArgument` /
MCP Invalid params): those backends' remote encryption service manages nonce
generation itself and exposes no parameter to accept a caller's choice, so a
supplied nonce used to be silently dropped rather than honored (go-xkms#1223).

Response (`EncryptResponse`, `types.go:182-189`):

```json
{ "ciphertext": "<base64>", "nonce": "<base64>", "tag": "<base64>", "iv": "<base64, CBC only>" }
```

## `POST /api/v1/keys/{id}/decrypt`

Request (`DecryptRequest`, `types.go:191-207`) adds `ciphertext`, `tag`, and
`tag_size` (int, 0 selects the cipher's full-length tag; must equal the
`TagSize` used to encrypt) to the same field set; `mode` must match the mode
used to encrypt. Response is `{"plaintext": "<base64>"}`.

Note that `EncryptRequest`/`DecryptRequest` have no `"ecb"` value documented
in the REST field comments even though the backend implements
`types.CipherModeECB` — confirm against
[`../key-management/api.md`](../key-management/api.md) and the handler
source (`pkg/api/rest/handlers.go:786-905`) before depending on ECB over
REST; this document does not claim it is wired through every transport
identically without checking that transport's own type definitions.

## GCM nonce mode is not a request field

`types.GCMNonceMode` (`GCMNonceModeExplicit`/`GCMNonceModeRandom`) is
resolved internally by `pkg/crypto/aead.NewGCMForFreshEncrypt` based on the
process's own FIPS posture and whether the caller supplied a nonce — it is
never a request parameter a client sets. A client that always leaves `nonce`
empty on `Encrypt` gets `GCMNonceModeRandom` automatically under
`GODEBUG=fips140=only` and `GCMNonceModeExplicit` (server-generated, but
still the caller-nonce-shaped construction) otherwise; supplying a
caller-chosen `nonce` under `fips140=only` fails with
`ErrArbitraryIVGCMUnavailable`. See
[`architecture.md`](architecture.md) §"GCM nonce modes and FIPS".

## `POST /api/v1/keys` — algorithm field, symmetric branch

`GenerateKeyHandler` (`pkg/api/rest/handlers.go:288-306`) resolves
`req.Algorithm` as follows: the literal `"symmetric"` selects AES-256-GCM;
any other string is first tried as an asymmetric algorithm
(`types.ParseKeyAlgorithm`) and, failing that, cast directly to
`types.SymmetricAlgorithm` — so `"aes128-gcm"`, `"aes192-gcm"`,
`"aes256-gcm"`, `"chacha20-poly1305"`, and `"xchacha20-poly1305"` (the exact
wire strings from [`engineering.md`](engineering.md)'s algorithm table) are
all accepted, whether or not a particular client's help text advertises
them. Generation requires the resolved backend's `KeyProvider()` to
implement `types.SymmetricKeyProvider`; a backend that does not returns a
400 (`handlers.go:349-353`).

## AEAD safety tracking is server-side only

No transport exposes `AEADSafetyTracker.GetBytesEncrypted` or nonce-history
directly; tracking happens inside the server process on every
`Encrypt`/`Decrypt` call and is invisible to the client beyond the errors it
can cause (`ErrNonceReused`, `ErrBytesLimitExceeded`, surfaced as encryption
failures). A client cannot query "how close is this key to its byte limit"
over any transport today.
