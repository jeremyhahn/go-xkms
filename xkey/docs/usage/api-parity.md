# API Parity Status

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: how the `Backend` interface (`pkg/xkms/keystore.go`) and the `XKMSService` (`pkg/xkms/service.go`) reach each client transport of xkmsd.

go-xkms reaches its key store through five client transports:

- **REST**: the routes in `pkg/api/rest/routes.go`, under `/api/v1`.
- **gRPC**: `KeystoreService` in `pkg/api/grpc/proto/xkmsv1/xkms.proto`.
- **MCP**: the JSON-RPC dispatch table `rpcMethodHandlers` (`pkg/api/mcp/server.go:247`).
- **QUIC**: HTTP/3 on the REST port, advertised through Alt-Svc
  (`pkg/server/server.go:2422`). The QUIC client
  (`pkg/api/transport/quic/transport.go`) calls the same `/api/v1` paths as
  REST, so every REST row below holds for QUIC too.
- **CLI**: `xkmsctl`, which drives any of these transports. Its `--transport`
  flag takes `rest`, `grpc`, `quic`, `mcp`, `unix` or `embedded`, and the
  default is `unix` (`cmd/xkmsctl/root.go:29`, `cmd/xkmsctl/config.go:29`).

## The Backend interface

`Backend` (`pkg/xkms/keystore.go:39`) has 28 methods:

| Group | Methods |
|-------|---------|
| Key generation | `GenerateRSA`, `GenerateECDSA`, `GenerateEd25519` |
| Key lifecycle | `GetKey`, `DeleteKey`, `ListKeys`, `RotateKey` |
| Crypto | `Signer`, `Decrypter` |
| Certificates | `SaveCert`, `GetCert`, `DeleteCert`, `SaveCertChain`, `GetCertChain`, `ListCerts`, `CertExists` |
| TLS | `GetTLSCertificate` |
| By key ID | `GetKeyByID`, `GetSignerByID`, `GetDecrypterByID` |
| Sealing | `Seal`, `Unseal`, `CanSeal` |
| In-process only | `Type`, `KeyProvider`, `CertStorage`, `SignerStore`, `Close` |

Symmetric keys use the separate `types.SymmetricKeyProvider` interface
(`pkg/types/types.go:2112`): `GenerateSymmetricKey`, `GetSymmetricKey` and
`SymmetricEncrypter`. No transport has its own symmetric operations. A
symmetric key is generated through the generic generate-key operation, which
switches to the backend's `SymmetricKeyProvider` when the request names a
symmetric algorithm (`pkg/xkms/servicer_key.go:119`). It is then used through
encrypt and decrypt.

## Transport matrix

A transport identifies a key by its ID in every operation, so the `*ByID`
methods are what the transports actually call.

| Backend method | REST | gRPC | MCP | xkmsctl |
|----------------|------|------|-----|---------|
| `GenerateRSA` / `ECDSA` / `Ed25519`, `GenerateSymmetricKey` | `POST /keys` | `GenerateKey` | `xkms.generateKey` | `key generate` |
| `GetKey` / `GetKeyByID` | `GET /keys/{id}` | `GetKey` | `xkms.getKey` | `key get` |
| `DeleteKey` | `DELETE /keys/{id}` | `DeleteKey` | `xkms.deleteKey` | `key delete` |
| `ListKeys` | `GET /keys` | `ListKeys` | `xkms.listKeys` | `key list` |
| `RotateKey` | `POST /keys/{id}/rotate` | `RotateKey` | `xkms.rotateKey` | `key rotate` |
| `Signer` / `GetSignerByID` | `POST /keys/{id}/sign` | `Sign` | `xkms.sign` | `key sign` |
| `Decrypter` / `GetDecrypterByID` | `POST /keys/{id}/decrypt` | `Decrypt` | `xkms.decrypt`, `xkms.asymmetricDecrypt` | `key decrypt` |
| `SymmetricEncrypter` (encrypt) | `POST /keys/{id}/encrypt` | `Encrypt` | `xkms.encrypt` | `key encrypt` |
| `SaveCert` | `POST /certs` | `SaveCert` | `xkms.saveCert` | `cert save` |
| `GetCert` | `GET /certs/{id}` | `GetCert` | `xkms.getCert` | `cert get` |
| `DeleteCert` | `DELETE /certs/{id}` | `DeleteCert` | `xkms.deleteCert` | `cert delete` |
| `ListCerts` | `GET /certs` | `ListCerts` | `xkms.listCerts` | `cert list` |
| `CertExists` | `HEAD /certs/{id}` | `CertExists` | `xkms.certExists` | `cert exists` |
| `SaveCertChain` | `POST /certs/{id}/chain` | `SaveCertChain` | `xkms.saveCertChain` | `cert save-chain` |
| `GetCertChain` | `GET /certs/{id}/chain` | `GetCertChain` | `xkms.getCertChain` | `cert get-chain` |
| `GetTLSCertificate` | `GET /tls/{id}` | `GetTLSCertificate` | `xkms.getTLSCertificate` | `tls get` |
| `Seal` | `POST /seal` | `Seal` | `xkms.seal` | `seal` |
| `Unseal` | `POST /unseal` | `Unseal` | `xkms.unseal` | `unseal` |
| `CanSeal` | `GET /seal/capability` | `CanSeal` | `xkms.canSeal` | `can-seal` |

Citations:

- REST: `routes.go:157-212`.
- gRPC: `xkms.proto:30-263`.
- MCP: `server.go:255-308`.

`Type`, `KeyProvider`, `CertStorage`, `SignerStore` and `Close` stay in-process
and have no transport operation.

## Operations beyond the Backend interface

| Operation | REST | gRPC | MCP | xkmsctl |
|-----------|------|------|-----|---------|
| Health | `GET`/`HEAD /health` | `Health` | `health` | — |
| Backends | `GET /backends`, `/backends/{id}` | `ListBackends`, `GetBackendInfo` | `xkms.listBackends`, `xkms.getBackend` | `backends list`, `backends info` |
| Verify | `POST /keys/{id}/verify` | `Verify` | `xkms.verify` | `key verify` |
| Asymmetric encrypt | `POST /keys/{id}/encrypt-asym` | `EncryptAsym` | `xkms.asymmetricEncrypt` | `key encrypt-asym` |
| Import parameters | `POST /keys/import-params` | `GetImportParameters` | `xkms.getImportParameters` | `key get-import-params` |
| Wrap / unwrap | `POST /keys/wrap`, `/keys/unwrap` | `WrapKey`, `UnwrapKey` | `xkms.wrapKey`, `xkms.unwrapKey` | `key wrap`, `key unwrap` |
| Wrap / unwrap by ID | `POST /keys/wrap-by-id`, `/keys/unwrap-by-id` | `WrapKeyByID`, `UnwrapKeyByID` | `xkms.wrapKeyByID`, `xkms.unwrapKeyByID` | `key wrap-by-id`, `key unwrap-by-id` |
| Import | `POST /keys/import` | `ImportKey` | `xkms.importKey` | `key import` |
| Export (wrapped) | `POST /keys/{id}/export` | `ExportKey` | `xkms.exportKey` | `key export` |
| Export material | `POST /keys/{id}/export-material` | `ExportKeyMaterial` | `xkms.exportKeyMaterial` | `key export-material` |
| Copy | `POST /keys/copy` | `CopyKey` | `xkms.copyKey` | `key copy` |
| ECDH derivation | `POST /keys/derive-ecdh` | `DeriveKeyECDH` | `xkms.deriveKeyECDH` | `key derive-ecdh` |
| Key derivation (HKDF, PBKDF2 and others) | not served | `DeriveKey` | `xkms.deriveKey` | — |
| Attestation | `POST /attest` | `AttestKey` | `xkms.attestKey` | `key attest` |

Both HTTP clients call `POST /api/v1/keys/derive` for key derivation
(`pkg/api/transport/rest/transport.go:839`, `pkg/api/transport/quic/transport.go:1050`),
but `routes.go` registers no such route. Generic key derivation is reachable
only over gRPC (`xkms.proto:123`) and MCP (`server.go:290`).

Key versions (`/keys/{id}/versions` and `key version …`), `POST /keys/rotate-all`
and the gRPC hardware-resident ECDH RPCs (`DeriveKeyECDHSecure`,
`UseResidentKey`, `GenerateEphemeralECDH`; `xkms.proto:137-147`) are also
outside the Backend interface. The PIV, CA, PIN, tenant, user, TPM-policy,
OIDC and SSH families are documented in their feature folders.

`pkg/api/keyops_parity_test/parity_test.go` checks that key operations give
the same results over REST and gRPC.

## XKMSService

`XKMSService` (`pkg/xkms/service.go:68`) puts the configured backends behind
one API. Most of it is package-level functions that act on a process-wide
singleton:

```go
import "github.com/jeremyhahn/go-xkms/pkg/xkms"

err := xkms.Initialize(&xkms.ServiceConfig{
    Backends:       map[string]xkms.Backend{"software": softwareBackend},
    KeyProviders:   map[string]xkms.Backend{},
    DefaultBackend: "software",
})
```

- `ServiceConfig` (`service.go:216`) holds `Backends` (full-service backends),
  `KeyProviders` (partial providers composed into backends) and
  `DefaultBackend`.
- `Initialize` (`service.go:507`) runs once. Later calls do nothing.
- `Get` (`service.go:233`) returns the singleton.
- `NewService` (`service.go:525`) builds a separate instance that is not the
  singleton.
- `Reset` (`service.go:584`) clears the singleton.

Key IDs use the format `backend:type:algo:keyname`. Every segment except
`keyname` is optional, so `my-key` and `pkcs11:::my-key` are both valid
(`pkg/xkms/keyid.go:27`).

| Group | Package functions |
|-------|-------------------|
| Backends | `GetBackend`, `DefaultBackend`, `BackendFor`, `Backends`, `KeyProviders`, `GetKeyProvider`, `GetBackendInfo`, `GetBackendCapabilities`, `RegisterServiceBackend`, `UnregisterBackend` |
| Keys | `GenerateKey`, `GenerateKeyWithBackend`, `Key`, `KeyByID`, `DeleteKey`, `DeleteKeyByID`, `ListKeys`, `RotateKey` |
| Crypto | `Signer`, `SignerByID`, `Sign`, `Verify`, `Decrypter`, `DecrypterByID`, `Encrypt`, `Decrypt` |
| Certificates | `Certificate`, `CertificateByID`, `SaveCertificate`, `SaveCertificateByID`, `DeleteCertificate`, `DeleteCertificateByID`, `ListCertificates`, `CertificateExists`, `CertificateExistsByID`, `CertificateChain`, `CertificateChainByID`, `SaveCertificateChain`, `SaveCertificateChainByID`, `ParseCertificateID` |
| TLS | `TLSCertificate`, `TLSCertificateByID` |
| Import and export | `GetImportParameters`, `WrapKey`, `UnwrapKey`, `WrapKeyByID`, `UnwrapKeyByID`, `ImportKey`, `ExportKey`, `CopyKey` |
| Symmetric | `GenerateSymmetricKey`, `GetSymmetricKey` |
| Sealing | `Seal`, `SealWithBackend`, `Unseal`, `UnsealWithBackend`, `CanSeal` |
| Lifecycle | `Initialize`, `NewService`, `Get`, `IsInitialized`, `Close`, `Reset` |
