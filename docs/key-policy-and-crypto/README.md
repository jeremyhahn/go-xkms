# Key policy and crypto utilities

Status: shipped ([#1681](../../../../issues/1681)): the key management RPCs
and the crypto utilities are served. SPEC row:
[key-policy-and-crypto](../SPEC.md#features).

go-quicbaas served key policy and crypto utilities over its own
`quicbaas.kms.v1` services, wrapping the go-xkms library. Those services move
into go-xkms's `xkms.v1` KeystoreService
(`pkg/api/grpc/proto/xkmsv1/xkms.proto`), so go-quicbaas re-exports one wire
surface per capability through `sdk/go`. DEK management is not here: go-qrdb
serves it through its `DEKClient`.

## Requirements

1. Every RPC below is declared on `xkms.v1` KeystoreService and served on
   every transport the existing key RPCs use, through gRPC handler, service
   layer and domain package; the handler holds no business logic.
2. Every RPC declares its permission with `(qrdb.v1.permission)`: reads take
   a read permission, mutations a write permission, and setting or clearing
   a safety limit an admin-grade write.
3. Every RPC is scoped to the caller's tenant through the service layer, as
   the existing key RPCs are; a request for another tenant's key is refused
   with a typed error.
4. Key and rotation policies, safety limits, key status and metadata persist
   in the deployment's one go-qrdb datastore through a feature-owned DAO in
   `pkg/dao`. There is no other store.
5. Keys, versions and backends are the existing keystore's; this feature adds
   no parallel key model.
6. Crypto utilities use the backends' keys and the Go standard library. FIPS
   is the standard library's job (`GODEBUG=fips140=only`): a non-approved
   algorithm is refused with a typed error, never a panic, and go-xkms keeps
   no allowlist of its own.
7. Every RPC has an `sdk/go` client method on the embedded and the remote
   transports.

## RPCs

Request and response fields follow go-quicbaas `api/proto/kms.proto`, which
defines their semantics.

| Group | RPCs | Status |
| --- | --- | --- |
| Key management (18) | GetPublicKey, RevokeKey, UpdateKeyStatus, GetKeyMetadata, UpdateKeyMetadata, SetKeyPolicy, GetKeyPolicy, DeleteKeyPolicy, SetKeyRotationPolicy, GetKeyRotationPolicy, DeleteKeyRotationPolicy, GetSupportedAlgorithms, BackendStatus, BackendTest, SetKeySafety, ClearKeySafety, SafetyCheck, SafetyReport | served |
| Crypto utilities (9) | Rewrap, EncryptBatch, DecryptBatch, GenerateDataKey, GenerateWrappedDataKey, GenerateHMAC, VerifyHMAC, GenerateRandom, Hash | served |

`quicbaas.kms.v1.SecretsManagement` is go-quicbaas-native and out of scope.
`quicbaas.kms.v1.DEKManagement` is go-qrdb's `DEKClient`.

## Key management

Declared at `xkms.proto:202`–`xkms.proto:294`; the domain is
`pkg/xkms/servicer_keymgmt.go`. Policies, rotation policies, safety limits,
status and metadata are one record per key in the `pkg/keypolicy` store, a
go-qrdb DAO entity (`pkg/keypolicy/store.go:57`).

| RPC | Permission | REST | What it does |
| --- | --- | --- | --- |
| GetPublicKey | keys:get | `GET /api/v1/keys/{id}/public-key` | The DER SubjectPublicKeyInfo (RFC 5280 §4.1.2.7) of the named or current version; a symmetric key is refused (`servicer_keymgmt.go:120`). |
| RevokeKey | keys:delete | `POST /api/v1/keys/{id}/revoke` | Takes the key out of service for good; it stays in its backend (`servicer_keymgmt.go:163`). |
| UpdateKeyStatus | keys:rotate | `POST /api/v1/keys/{id}/status` | Enables or disables the key, or one version; a revoked key cannot change status (`servicer_keymgmt.go:184`). |
| GetKeyMetadata | keys:get | `GET /api/v1/keys/{id}/metadata` | The backend's algorithm and exportability with the record's status, name, tags and policy (`servicer_keymgmt.go:240`). |
| UpdateKeyMetadata | keys:rotate | `PUT /api/v1/keys/{id}/metadata` | Sets name and description, merges and removes tags (`servicer_keymgmt.go:257`). |
| SetKeyPolicy | keys:rotate | `PUT /api/v1/keys/{id}/policy` | Sets or replaces the access policy, each with the next version; a policy narrows RBAC, never widens it (`servicer_keymgmt.go:295`). |
| GetKeyPolicy | keys:get | `GET /api/v1/keys/{id}/policy` | The access policy, nil when RBAC alone governs the key (`servicer_keymgmt.go:355`). |
| DeleteKeyPolicy | keys:delete | `DELETE /api/v1/keys/{id}/policy` | Removes the access policy (`servicer_keymgmt.go:372`). |
| SetKeyRotationPolicy | keys:rotate | `PUT /api/v1/keys/{id}/rotation-policy` | Sets the rotation interval and next rotation; with rotation required, the key is refused once that time passes (`servicer_keymgmt.go:380`). |
| GetKeyRotationPolicy | keys:get | `GET /api/v1/keys/{id}/rotation-policy` | The rotation policy, nil when none (`servicer_keymgmt.go:431`). |
| DeleteKeyRotationPolicy | keys:delete | `DELETE /api/v1/keys/{id}/rotation-policy` | Removes the rotation policy (`servicer_keymgmt.go:447`). |
| SetKeySafety | keys:rotate | `PUT /api/v1/keys/{id}/safety` | Usage limits on a symmetric AEAD key; an AES-GCM operation limit above 2^32 is refused (NIST SP 800-38D §8.3), ChaCha20-Poly1305 is bounded by RFC 8439 §4 (`servicer_keymgmt.go:457`). |
| ClearKeySafety | keys:rotate | `DELETE /api/v1/keys/{id}/safety` | Removes the usage limits (`servicer_keymgmt.go:494`). |
| SafetyCheck | keys:get | `GET /api/v1/safety/check` | The tenant's keys at or past their warning threshold (`servicer_keymgmt.go:518`). |
| SafetyReport | keys:get | `GET /api/v1/safety/report` | Usage of every key with limits, with warning and critical counts (`servicer_keymgmt.go:539`). |
| GetSupportedAlgorithms | keys:list | `GET /api/v1/backend/algorithms` | The key algorithms the backend declares in `Capabilities().KeyAlgorithms` (`pkg/types/types.go:1716`), named through the transport name maps; a shape without a transport name (an ML-DSA or ML-KEM parameter set) is left out, and under `GODEBUG=fips140=only` so are ChaCha20-Poly1305, XChaCha20-Poly1305 and X25519 (`servicer_keymgmt.go:625`). The Algorithms RPC reads the same declaration (`algorithms.go:39`), so the two agree. |
| BackendStatus | backends:read | `GET /api/v1/backend/status` | Type, capabilities and health (`servicer_keymgmt.go:639`). |
| BackendTest | backends:read | `POST /api/v1/backend/test` | A non-destructive seal round trip under the existing default sealing key, admitted through its status, policy and usage count; a failed or refused trip is `success: false`; a backend that cannot seal, or has no default sealing key yet, is refused and nothing is created (`servicer_keymgmt.go:703`, `servicer_keymgmt.go:734`). |

The routes are at `pkg/api/rest/routes.go:222`–`239`; the MCP methods are
`xkms.getPublicKey` … `xkms.safetyReport` (`pkg/api/mcp/server.go:302`–`319`).

Refusals are typed and classified by `KeyPolicyClassOf`
(`pkg/api/apierrors/tables.go`): an invalid policy, key kind or record key is
`InvalidArgument`; a policy the backend cannot enforce, or a backend that
cannot be tested, is `Unimplemented`; a forbidden status change or an
unavailable key is `FailedPrecondition`; a policy refusal is
`PermissionDenied`; an exhausted usage limit is `ResourceExhausted`; and a
service without a key policy store (`ErrKeyPoliciesNotConfigured`,
`pkg/xkms/key_policies.go:27`) is `Unavailable`.

Every key-use path is admitted through the key's record by `admitKey`
(`pkg/xkms/key_policies.go:134`): sign, verify, encrypt, decrypt, MAC, seal,
unseal, derive, ECDH, wrap and unwrap by ID, and the export paths (ExportKey,
ExportKeyMaterial, CopyKey and the key WrapKeyByID wraps). A revoked or
disabled key, or an operation its policy does not allow, is refused before
the backend is reached. The export paths admit `OpExportKey`
(`pkg/keypolicy/record.go:71`), which no policy can name: a key whose policy
restricts its operations is never exported. Wrapping under an AES-GCM key
counts toward its usage limits. GetKey and AttestKey release no key material
and stay readable for a revoked key. GetPublicKey falls back to the backend's
signer or decrypter for a key whose private key never leaves its KMS
(`pkg/xkms/servicer_keymgmt.go:161`).

## Crypto utilities

Declared at `xkms.proto:144`–`xkms.proto:189`; the domain is
`pkg/xkms/servicer_cryptoutil.go`.

| RPC | Permission | REST | What it does |
| --- | --- | --- | --- |
| Rewrap | keys:decrypt | `POST /api/v1/keys/rewrap` | Decrypts with the source key and encrypts under the target key (default: the source key's current version); the plaintext is wiped (`servicer_cryptoutil.go:37`). |
| EncryptBatch | keys:encrypt | `POST /api/v1/keys/{id}/encrypt-batch` | 1 to 100 items under the key's current version; a failed item carries its error in its own slot (`servicer_cryptoutil.go:72`). |
| DecryptBatch | keys:decrypt | `POST /api/v1/keys/{id}/decrypt-batch` | As EncryptBatch, across key versions (`servicer_cryptoutil.go:117`). |
| GenerateDataKey | keys:encrypt | `POST /api/v1/keys/{id}/data-key` | A random 16, 24 or 32-byte key (default 32), returned in plaintext and wrapped by the key (`servicer_cryptoutil.go:172`). |
| GenerateWrappedDataKey | keys:encrypt | `POST /api/v1/keys/{id}/wrapped-data-key` | As GenerateDataKey, wrapped only (`servicer_cryptoutil.go:182`). |
| GenerateHMAC | keys:sign | `POST /api/v1/keys/{id}/hmac` | HMAC over the symmetric key's current version, SHA-256 by default (`servicer_cryptoutil.go:238`). |
| VerifyHMAC | keys:verify | `POST /api/v1/keys/{id}/hmac/verify` | Constant-time check against the named or every enabled version; a mismatch is `valid: false`, not an error (`servicer_cryptoutil.go:272`). |
| GenerateRandom | keys:verify | `POST /api/v1/random` | 1 to 1024 bytes from `crypto/rand` (`servicer_cryptoutil.go:337`). |
| Hash | keys:verify | `POST /api/v1/hash` | A digest, SHA-256 by default (`servicer_cryptoutil.go:355`). |

Rewrap is gated on keys:decrypt alone on every transport; the target encrypt
runs in the same tenant. The routes are at `pkg/api/rest/routes.go:211`–`219`;
the batch, HMAC and hash routes take caller data and use the 4 MiB bulk body
limit. MCP
methods are `xkms.rewrap` … `xkms.hash` (`pkg/api/mcp/server.go:289`–`297`).

Refusals are typed and map to `InvalidArgument` / 400: `ErrBatchSize`,
`ErrDataKeySize`, `ErrRandomLength`, `ErrInvalidHashFunction` (unknown, `NONE`
or unusable hash, `servicer_cryptoutil.go:370`), and `ErrHMACRefused` when the
standard library refuses the MAC, for example a key under 112 bits with
`GODEBUG=fips140=only` (`servicer_cryptoutil.go:324`).

## Name mapping

An existing `xkms.v1` RPC covers a `quicbaas.kms.v1` name only if it returns
what the quicbaas response carries. None does, so all 27 names are added.

| quicbaas.kms.v1 | Candidate in xkms.v1 | Decision | Why |
| --- | --- | --- | --- |
| GetPublicKey | `GetKey` (`xkms.proto:40`) | added | `GetKeyRequest` (`xkms.proto:1280`) has no version selector, and `GetKeyResponse` (`xkms.proto:1286`) returns the current version's PEM, not a chosen version's DER (PKIX) key and algorithm. |
| GetSupportedAlgorithms | `Algorithms` (`xkms.proto:561`) | added | `AlgorithmsResponse` (`xkms.proto:3162`) lists signing and key-encapsulation algorithms only; the quicbaas response names the symmetric AEAD algorithms (AES-GCM, ChaCha20-Poly1305) too. |
| BackendStatus | `GetBackendInfo` (`xkms.proto:25`), `Health` (`xkms.proto:17`) | added | `BackendInfo` (`xkms.proto:1192`) carries capability flags but no health status, device, region or PCR banks; `HealthResponse` (`xkms.proto:1186`) is the service's status and version only. |
| the other 24 | none of the same name | added | No `xkms.v1` RPC has the name or the behaviour. |
