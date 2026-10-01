// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package mcp

import (
	"encoding/json"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// JSONRPCRequest represents a JSON-RPC 2.0 request
type JSONRPCRequest struct {
	JSONRPC       string          `json:"jsonrpc"`
	Method        string          `json:"method"`
	Params        json.RawMessage `json:"params,omitempty"`
	ID            interface{}     `json:"id,omitempty"`
	CorrelationID string          `json:"correlation_id,omitempty"` // Optional correlation ID for distributed tracing
}

// JSONRPCResponse represents a JSON-RPC 2.0 response
type JSONRPCResponse struct {
	JSONRPC       string        `json:"jsonrpc"`
	Result        interface{}   `json:"result,omitempty"`
	Error         *JSONRPCError `json:"error,omitempty"`
	ID            interface{}   `json:"id,omitempty"`
	CorrelationID string        `json:"correlation_id,omitempty"` // Correlation ID returned in response
}

// JSONRPCError represents a JSON-RPC 2.0 error
type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// JSON-RPC 2.0 error codes
const (
	ErrCodeParseError     = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternalError  = -32603

	// Authorization codes. JSON-RPC 2.0 reserves -32000..-32099 for
	// implementation-defined server errors; the standard code set has no
	// authentication or authorization member. These mirror the HTTP statuses
	// the REST and QUIC transports return for the same decisions (401 and
	// 403) and follow the ACME MCP surface's use of the reserved range
	// (pkg/acme/api/server/server.go).

	// ErrCodeUnauthorized reports a request that carried no authenticated
	// identity for a method that requires one — the REST/QUIC 401.
	ErrCodeUnauthorized = -32002

	// ErrCodeForbidden reports an authenticated caller that lacks the qrdb
	// role grant required by the method — the REST/QUIC 403. It also reports
	// a tenant-scoped caller whose tenant carries no registered barrier (see
	// pkg/api/tenantgate.ErrTenantNotFound), mirroring the REST/QUIC/gRPC
	// 403/PermissionDenied for the same condition.
	ErrCodeForbidden = -32003

	// ErrCodeServiceUnavailable reports a tenant-scoped caller whose tenant
	// barrier exists but is currently sealed (see
	// pkg/api/tenantgate.ErrTenantSealed) — the REST/QUIC 503 and the gRPC
	// Unavailable status.
	ErrCodeServiceUnavailable = -32004
)

// JSONRPCNotification represents a JSON-RPC 2.0 notification (no ID)
type JSONRPCNotification struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// HealthResult represents the result of a health check
type HealthResult struct {
	Status string `json:"status"`
}

// BackendInfo represents information about a backend
type BackendInfo struct {
	ID             string             `json:"id"`
	Type           string             `json:"type"`
	HardwareBacked bool               `json:"hardware_backed"`
	Capabilities   types.Capabilities `json:"capabilities"`
}

// ListBackendsResult represents the result of listing backends
type ListBackendsResult struct {
	Backends   []BackendInfo           `json:"backends"`
	Pagination *transport.PageResponse `json:"pagination,omitempty"`
}

// GetBackendParams represents parameters for looking up a single backend.
type GetBackendParams struct {
	Backend string `json:"backend"`
}

// GenerateKeyParams represents parameters for key generation. Algorithm is
// required (rsa, ecdsa, ed25519, aes128-gcm, aes192-gcm, aes256-gcm, ...);
// KeyType is the key's purpose (signing, encryption, ca, tls, ...) and is no
// longer read as an algorithm name when Algorithm is empty.
type GenerateKeyParams struct {
	KeyID      string `json:"key_id"`
	Backend    string `json:"backend"`
	KeyType    string `json:"key_type"`
	KeySize    int    `json:"key_size,omitempty"`
	Curve      string `json:"curve,omitempty"`
	Algorithm  string `json:"algorithm"`
	Exportable bool   `json:"exportable,omitempty"`
	Sensitive  bool   `json:"sensitive,omitempty"` // CKA_SENSITIVE: plaintext is never released
	// TPMPolicy names the TPM policy a TPM2 key is bound to; empty is the
	// built-in "platform" policy.
	TPMPolicy string `json:"tpm_policy,omitempty"`
}

// GenerateKeyResult represents the result of key generation
type GenerateKeyResult struct {
	KeyID        string `json:"key_id"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
}

// DeleteKeyParams represents parameters for key deletion
type DeleteKeyParams struct {
	KeyID   string `json:"key_id"`
	Backend string `json:"backend"`
}

// GetKeyParams represents parameters for getting a key
type GetKeyParams struct {
	KeyID   string `json:"key_id"`
	Backend string `json:"backend"`
}

// GetKeyResult represents the result of getting a key
type GetKeyResult struct {
	KeyID        string `json:"key_id"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	Backend      string `json:"backend"`
	// KeyVersion is the key's current version, the one sign and encrypt use.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// SignParams represents parameters for signing.
//
// Every field below is forwarded verbatim to transport.SignRequest; see that
// type for the authoritative semantics. This struct exists only to give the
// JSON-RPC surface its own parameter shape, not to reinterpret any parameter.
type SignParams struct {
	KeyID   string `json:"key_id"`
	Backend string `json:"backend"`
	Data    []byte `json:"data"`
	Hash    string `json:"hash"`
	// DataIsDigest states that Data is already the digest and must not be
	// hashed again, while Hash still names which digest produced it.
	// RSASSA-PSS needs both facts at once, so they are separate fields.
	DataIsDigest bool `json:"data_is_digest,omitempty"`
	// Padding selects the RSA signature padding scheme: "" or "pkcs1v15"
	// (default, PKCS#1 v1.5) or "pss" (RSASSA-PSS).
	Padding string `json:"padding,omitempty"`
	// SaltLength is the RSA-PSS salt length in bytes. Zero selects
	// rsa.PSSSaltLengthAuto. Ignored unless Padding is "pss".
	SaltLength int `json:"salt_length,omitempty"`
	// PreHash selects the pre-hashed EdDSA variant (Ed25519ph) per RFC 8032
	// Table 73. Only meaningful for Ed25519 keys.
	PreHash bool `json:"pre_hash,omitempty"`
	// Context is the optional EdDSA context string (Ed25519ctx).
	Context []byte `json:"context,omitempty"`
}

// SignResult represents the result of signing
type SignResult struct {
	Signature interface{} `json:"signature"`
	// Algorithm names the key algorithm that produced the signature, as
	// reported by the service layer.
	Algorithm string `json:"algorithm,omitempty"`
	// KeyVersion is the key version that produced the output: always the
	// current one.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// VerifyParams represents parameters for verification. Its parameters mirror
// SignParams' and must match those used to produce Signature.
type VerifyParams struct {
	KeyID     string      `json:"key_id"`
	Backend   string      `json:"backend"`
	Data      []byte      `json:"data"`
	Signature interface{} `json:"signature"`
	Hash      string      `json:"hash"`
	// DataIsDigest states that Data is already the digest. See
	// SignParams.DataIsDigest.
	DataIsDigest bool `json:"data_is_digest,omitempty"`
	// Padding selects the RSA signature padding scheme. See
	// SignParams.Padding.
	Padding string `json:"padding,omitempty"`
	// SaltLength is the RSA-PSS salt length in bytes the signature is
	// expected to use. Zero selects rsa.PSSSaltLengthAuto (auto-detect).
	SaltLength int `json:"salt_length,omitempty"`
	// PreHash selects the pre-hashed EdDSA variant. See SignParams.PreHash.
	PreHash bool `json:"pre_hash,omitempty"`
	// Context is the optional EdDSA context string. See SignParams.Context.
	Context []byte `json:"context,omitempty"`
	// KeyVersion optionally names the key version to use; it must be
	// enabled. Zero chooses one; see transport.VerifyRequest.KeyVersion and
	// transport.DecryptRequest.KeyVersion.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// VerifyResult represents the result of verification
type VerifyResult struct {
	Valid bool `json:"valid"`
	// KeyVersion is the key version that verified or decrypted.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// SubscribeParams represents parameters for event subscription
type SubscribeParams struct {
	Events []string `json:"events"`
}

// EventNotification represents an event notification
type EventNotification struct {
	Event string      `json:"event"`
	KeyID string      `json:"key_id,omitempty"`
	Data  interface{} `json:"data,omitempty"`
}

// RotateKeyParams represents parameters for key rotation
type RotateKeyParams struct {
	KeyID   string `json:"key_id"`
	Backend string `json:"backend"`
}

// RotateKeyResult represents the result of key rotation
type RotateKeyResult struct {
	KeyID        string `json:"key_id"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	// KeyType is the rotated key's type, which rotation preserves.
	KeyType string `json:"key_type,omitempty"`
	// KeyVersion is the version the rotation created, now current.
	KeyVersion uint32 `json:"key_version,omitempty"`
	// CertificateReissueRequired reports that the key has a certificate,
	// which still certifies the previous version.
	CertificateReissueRequired bool `json:"certificate_reissue_required,omitempty"`
}

// DecryptParams represents parameters for decryption
type DecryptParams struct {
	KeyID          string `json:"key_id"`
	Backend        string `json:"backend"`
	Ciphertext     []byte `json:"ciphertext"`
	Nonce          []byte `json:"nonce,omitempty"`           // For symmetric decryption
	Tag            []byte `json:"tag,omitempty"`             // For symmetric decryption
	AdditionalData []byte `json:"additional_data,omitempty"` // For symmetric decryption with AAD
	// GCMNonceMode is the value the matching EncryptResult.GCMNonceMode
	// reported; see its doc comment. Required, unchanged, to decrypt an
	// AES-GCM ciphertext produced under GODEBUG=fips140=only.
	GCMNonceMode string `json:"gcm_nonce_mode,omitempty"`
	// Mode selects the cipher mode of operation: "" (default AEAD, AES-GCM or
	// ChaCha20-Poly1305), "cbc" (unpadded AES-CBC), or "cbc-pad" (AES-CBC with
	// PKCS#7 padding). Must match the Mode used to produce Ciphertext.
	Mode string `json:"mode,omitempty"`
	// IV is the AES-CBC initialization vector used at encryption time,
	// exactly 16 bytes. Required when Mode is "cbc" or "cbc-pad".
	IV []byte `json:"iv,omitempty"`
	// TagSize is the AEAD authentication tag length in bytes that Tag
	// carries; 0 selects the cipher's full-length tag. It must equal the
	// TagSize used to encrypt.
	TagSize int `json:"tag_size,omitempty"`
	// Padding selects the RSA decryption scheme for an asymmetric key:
	// "" or "pkcs1v15" (default), or "oaep". This handler used to force
	// OAEP-SHA-256 unconditionally, so a PKCS#1 v1.5 ciphertext could not be
	// decrypted here at all and an OAEP ciphertext under any other digest
	// failed with an error that read like corruption.
	Padding string `json:"padding,omitempty"`
	// Hash names the OAEP digest (e.g. "SHA-256"). Ignored unless Padding is
	// "oaep"; empty selects SHA-1, which is OAEP's own default.
	Hash string `json:"hash,omitempty"`
	// Label is the optional OAEP label. Ignored unless Padding is "oaep".
	Label []byte `json:"label,omitempty"`
	// KeyVersion optionally names the key version to use; it must be
	// enabled. Zero chooses one; see transport.VerifyRequest.KeyVersion and
	// transport.DecryptRequest.KeyVersion.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// DecryptResult represents the result of decryption
type DecryptResult struct {
	Plaintext []byte `json:"plaintext"`
	// KeyVersion is the key version that verified or decrypted.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// EncryptParams represents parameters for encryption
type EncryptParams struct {
	KeyID          string `json:"key_id"`
	Backend        string `json:"backend"`
	Plaintext      []byte `json:"plaintext"`
	AdditionalData []byte `json:"additional_data,omitempty"` // For AEAD (authenticated encryption with associated data)
	// Nonce optionally supplies the AEAD nonce to use. If empty, the backend
	// generates a random one and returns it in EncryptResult.Nonce. Only
	// meaningful for the default AEAD mode; AES-CBC uses IV instead.
	Nonce []byte `json:"nonce,omitempty"`
	// Mode selects the cipher mode of operation: "" (default AEAD, AES-GCM or
	// ChaCha20-Poly1305), "cbc" (unpadded AES-CBC; Plaintext must already be a
	// whole number of AES blocks), or "cbc-pad" (AES-CBC with PKCS#7 padding).
	Mode string `json:"mode,omitempty"`
	// IV supplies the AES-CBC initialization vector, exactly 16 bytes. Ignored
	// for the default AEAD mode. If empty with a CBC Mode, a random IV is
	// generated and returned in EncryptResult.IV.
	IV []byte `json:"iv,omitempty"`
	// TagSize is the AEAD authentication tag length in bytes; 0 selects the
	// cipher's full-length tag. AES-GCM admits 12-16 bytes per NIST
	// SP 800-38D section 5.2.1.2.
	TagSize int `json:"tag_size,omitempty"`
}

// EncryptResult represents the result of encryption
type EncryptResult struct {
	Ciphertext []byte `json:"ciphertext"` // base64 encoded in JSON
	Nonce      []byte `json:"nonce"`      // base64 encoded in JSON
	Tag        []byte `json:"tag"`        // base64 encoded in JSON
	// IV is the AES-CBC initialization vector used for encryption. Populated
	// only when the request's Mode was "cbc" or "cbc-pad".
	IV []byte `json:"iv,omitempty"`
	// GCMNonceMode mirrors transport.EncryptResponse.GCMNonceMode: "" for a
	// caller- or RNG-supplied nonce, "random" when GODEBUG=fips140=only
	// forced this encryption through cipher.NewGCMWithRandomNonce (see
	// docs/fips/README.md "AEAD construction"). Echo it back unchanged on
	// the matching DecryptParams; Decrypt cannot infer it from the
	// ciphertext bytes alone.
	GCMNonceMode string `json:"gcm_nonce_mode,omitempty"`
	// KeyVersion is the key version that produced the output: always the
	// current one.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// SaveCertParams represents parameters for saving a certificate
type SaveCertParams struct {
	KeyID   string `json:"key_id"`
	CertPEM string `json:"cert_pem"`
}

// GetCertParams represents parameters for getting a certificate
type GetCertParams struct {
	KeyID string `json:"key_id"`
}

// GetCertResult represents the result of getting a certificate
type GetCertResult struct {
	KeyID   string `json:"key_id"`
	CertPEM string `json:"cert_pem"`
}

// DeleteCertParams represents parameters for deleting a certificate
type DeleteCertParams struct {
	KeyID string `json:"key_id"`
}

// ListCertsResult represents the result of listing certificates
type ListCertsResult struct {
	KeyIDs     []string                `json:"key_ids"`
	Pagination *transport.PageResponse `json:"pagination,omitempty"`
}

// CertExistsParams represents parameters for checking certificate existence
type CertExistsParams struct {
	KeyID string `json:"key_id"`
}

// CertExistsResult represents the result of checking certificate existence
type CertExistsResult struct {
	Exists bool `json:"exists"`
}

// ListKeysParams represents optional parameters for listing keys.
// When Backend is empty, keys from all backends are returned.
// Pagination fields are optional; when Page is 0 all results are returned.
type ListKeysParams struct {
	Backend   string `json:"backend,omitempty"`
	Page      int    `json:"page,omitempty"`
	PageSize  int    `json:"page_size,omitempty"`
	SortField string `json:"sort_field,omitempty"`
	SortOrder int    `json:"sort_order,omitempty"`
}

// ListKeysResult represents the result of listing keys
type ListKeysResult struct {
	Keys       []KeyInfo               `json:"keys"`
	Pagination *transport.PageResponse `json:"pagination,omitempty"`
}

// KeyInfo represents information about a key, matching the REST API format.
type KeyInfo struct {
	KeyID        string `json:"key_id"`
	KeyType      string `json:"key_type"`
	Algorithm    string `json:"algorithm,omitempty"`
	Backend      string `json:"backend"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	// KeyVersion is the key's current version, the one sign and encrypt use.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// SaveCertChainParams represents parameters for saving a certificate chain
type SaveCertChainParams struct {
	KeyID     string   `json:"key_id"`
	ChainPEMs []string `json:"chain_pems"`
}

// GetCertChainParams represents parameters for getting a certificate chain
type GetCertChainParams struct {
	KeyID string `json:"key_id"`
}

// GetCertChainResult represents the result of getting a certificate chain
type GetCertChainResult struct {
	KeyID     string   `json:"key_id"`
	ChainPEMs []string `json:"chain_pems"`
}

// GetTLSCertificateParams represents parameters for getting a TLS certificate
type GetTLSCertificateParams struct {
	KeyID   string `json:"key_id"`
	Backend string `json:"backend"`
}

// GetImportParametersParams represents parameters for getting import parameters
type GetImportParametersParams struct {
	KeyID     string `json:"key_id"`
	Backend   string `json:"backend"`
	Algorithm string `json:"algorithm"` // Wrapping algorithm
	// KeyType names the ALGORITHM of the key the caller intends to import,
	// with the vocabulary ImportKeyParams.KeyType takes ("rsa", "ecdsa",
	// "ed25519", "symmetric" or "aes"), so the backend can say in key_spec
	// what it will accept. Distinct from Algorithm, the WRAPPING algorithm.
	// Absent, the backend cannot name a spec and answers UNKNOWN, and the
	// caller learns the intended algorithm only at import time.
	KeyType string `json:"key_type,omitempty"`
	// KeySize is the modulus size in bits for RSA, or the key length in bits
	// for symmetric material, as on ImportKeyParams.
	KeySize int `json:"key_size,omitempty"`
	// Curve names the EC curve for an "ecdsa" key, as on ImportKeyParams.
	Curve string `json:"curve,omitempty"`
	// TenantID is refused when set. The tenant an operation runs under is the
	// authenticated caller's own, never one the request names; see
	// ErrTenantIDNotAccepted. The field exists so a caller that sends one is
	// told so rather than having it silently discarded by the decoder.
	TenantID string `json:"tenant_id,omitempty"`
}

// GetImportParametersResult represents the import parameters response
type GetImportParametersResult struct {
	WrappingPublicKeyPEM string  `json:"wrapping_public_key_pem"`
	ImportToken          []byte  `json:"import_token,omitempty"`
	Algorithm            string  `json:"algorithm"`
	ExpiresAt            *string `json:"expires_at,omitempty"` // ISO 8601 format
	KeySpec              string  `json:"key_spec,omitempty"`
}

// WrapKeyParams represents parameters for wrapping key material
type WrapKeyParams struct {
	KeyMaterial []byte `json:"key_material"`
	// WrappingPublicKeyPEM is the wrapping public key as PEM text. The
	// corresponding transport.WrapKeyRequest field carries DER bytes, so
	// pkg/api/transport/mcp encodes on the way out; the handler decodes it with
	// pem.Decode and x509.ParsePKIXPublicKey. Assigning the DER straight across
	// yields base64, which is non-empty and fails pem.Decode -- see go-xkms#255.
	WrappingPublicKeyPEM string `json:"wrapping_public_key_pem"`
	ImportToken          []byte `json:"import_token,omitempty"`
	Algorithm            string `json:"algorithm"`
	// Backend names the backend that performs the wrap. Empty selects the
	// caller's default. It was absent until go-xkms#255, so every wrap ran
	// against the process default whatever the caller asked for.
	Backend string `json:"backend,omitempty"`
	// KeySpec is the key spec from GetImportParameters. Backends whose import
	// ceremony is key-spec aware -- AWS KMS most visibly -- need it back to
	// wrap for the right target key kind.
	KeySpec string `json:"key_spec,omitempty"`
}

// WrapKeyResult represents the wrapped key response
type WrapKeyResult struct {
	WrappedKey  []byte            `json:"wrapped_key"`
	Algorithm   string            `json:"algorithm"`
	ImportToken []byte            `json:"import_token,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// UnwrapKeyParams represents parameters for unwrapping key material
type UnwrapKeyParams struct {
	// WrappedKey carries the wrapped material. The name is "wrapped_key", the
	// vocabulary every params struct on this transport uses; the corresponding
	// transport.UnwrapKeyRequest field is "wrapped_key_material".
	// pkg/api/transport/mcp maps between them by name, so the two cannot drift
	// silently again -- they had, and this field arrived nil on every call
	// (go-xkms#255, the same defect as go-xkms#159 on the import path).
	WrappedKey  []byte `json:"wrapped_key"`
	Algorithm   string `json:"algorithm"`
	ImportToken []byte `json:"import_token,omitempty"`
	// WrappingPublicKey is the wrapping public key as PEM text; the request
	// field of the same name carries DER bytes. See WrapKeyParams.
	WrappingPublicKey string            `json:"wrapping_public_key"` // PEM format
	Metadata          map[string]string `json:"metadata,omitempty"`
	// Backend names the backend that performs the unwrap. Empty selects the
	// caller's default. Absent until go-xkms#255.
	Backend string `json:"backend,omitempty"`
	// KeySpec is the key spec the material was wrapped for, as returned by
	// GetImportParameters.
	KeySpec string `json:"key_spec,omitempty"`
}

// UnwrapKeyResult represents the unwrapped key response
type UnwrapKeyResult struct {
	KeyMaterial []byte `json:"key_material"`
}

// ImportKeyParams represents parameters for importing key material
type ImportKeyParams struct {
	KeyID   string `json:"key_id"`
	Backend string `json:"backend"`
	// KeyType names the ALGORITHM of the key being imported -- "rsa", "ecdsa",
	// "ed25519", "symmetric" or "aes" -- and is REQUIRED. It is the same field,
	// with the same vocabulary, that the gRPC and REST imports take.
	//
	// Distinct from Algorithm below, which is the WRAPPING algorithm. The two
	// were easy to confuse because this field did not exist, so the only
	// algorithm a caller could name was the wrong one, and the attributes the
	// import built described no algorithm at all.
	KeyType string `json:"key_type"`
	// KeySize is the modulus size in bits for RSA, or the key length in bits
	// for symmetric material. Zero selects the transport-wide default
	// (RSA-2048, AES-256).
	KeySize int `json:"key_size,omitempty"`
	// Curve names the EC curve for an "ecdsa" import ("P-256", "P-384",
	// "P-521"). Empty selects P-256, as it does on every other transport.
	Curve string `json:"curve,omitempty"`
	// WrappedKey carries the wrapped key material. The name is "wrapped_key",
	// which is the vocabulary every other params struct on this transport uses
	// (CopyKeyParams, UnwrapKeyParams, ExportKeyResult); it is deliberately NOT
	// renamed to the transport struct's "wrapped_key_material", because that
	// would leave import as the one MCP call spelling it differently.
	// pkg/api/transport/mcp builds this struct by name instead, so the two
	// sides are linked at compile time -- see go-xkms#159, where they were not
	// and every import over that transport arrived with no key material.
	WrappedKey  []byte            `json:"wrapped_key"`
	Algorithm   string            `json:"algorithm"`
	ImportToken []byte            `json:"import_token,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	// AESKeySize is the symmetric size fallback pkg/xkms.buildImportKeyAttributes
	// documents, so the same call behaves the same over gRPC, REST and MCP. The
	// sibling CopyKeyParams has always carried it; this struct dropped it, and
	// a symmetric import over this transport failed on a zero key size.
	AESKeySize int `json:"aes_key_size,omitempty"`
	// Hash names the digest recorded on the imported key.
	Hash string `json:"hash,omitempty"`
	// Partition names the sub-namespace the imported key is stored in, as it
	// does for the generate and gRPC/REST import paths.
	Partition string `json:"partition,omitempty"`
	// Exportable records whether the imported key may leave the backend
	// again; unset keeps the write-once default (symmetric exportable,
	// asymmetric not). See transport.ImportKeyRequest.
	Exportable *bool `json:"exportable,omitempty"`
	// Sensitive carries PKCS#11 CKA_SENSITIVE, as GenerateKeyParams does.
	Sensitive bool `json:"sensitive,omitempty"`
	// TenantID is refused when set. The tenant an import runs under is the
	// authenticated caller's own, never one the request names; see
	// ErrTenantIDNotAccepted. The field exists so a caller that sends one is
	// told so rather than having it silently discarded by the decoder.
	TenantID string `json:"tenant_id,omitempty"`
}

// ExportKeyParams represents parameters for exporting a key
type ExportKeyParams struct {
	KeyID     string `json:"key_id"`
	Backend   string `json:"backend"`
	Algorithm string `json:"algorithm"`
}

// ExportKeyResult represents the export key response
type ExportKeyResult struct {
	WrappedKey  []byte            `json:"wrapped_key"`
	Algorithm   string            `json:"algorithm"`
	ImportToken []byte            `json:"import_token,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// AsymmetricEncryptParams represents parameters for asymmetric encryption (RSA)
type AsymmetricEncryptParams struct {
	KeyID     string `json:"key_id"`
	Backend   string `json:"backend"`
	Plaintext []byte `json:"plaintext"`
	// Hash names the RSA-OAEP digest (e.g. "SHA-384"). Empty selects
	// SHA-256. The digest is part of the ciphertext's construction, so a
	// caller that asks for one hash and gets another produces a blob its
	// intended recipient cannot open.
	Hash string `json:"hash,omitempty"`
}

// AsymmetricEncryptResult represents the result of asymmetric encryption
type AsymmetricEncryptResult struct {
	Ciphertext []byte `json:"ciphertext"`
	// KeyVersion is the key version that produced the output: always the
	// current one.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// AsymmetricDecryptParams represents parameters for asymmetric decryption (RSA)
type AsymmetricDecryptParams struct {
	KeyID      string `json:"key_id"`
	Backend    string `json:"backend"`
	Ciphertext []byte `json:"ciphertext"`
	// Padding selects the RSA decryption scheme: "" or "pkcs1v15", or
	// "oaep". Empty defaults to "oaep" here rather than to PKCS#1 v1.5,
	// because this method is the counterpart of xkms.asymmetricEncrypt,
	// which only ever produces OAEP ciphertexts. See DecryptParams.Padding
	// for the general-purpose decrypt method's default.
	Padding string `json:"padding,omitempty"`
	// Hash names the OAEP digest. Empty selects SHA-256, matching
	// xkms.asymmetricEncrypt's own default.
	Hash string `json:"hash,omitempty"`
	// Label is the optional OAEP label.
	Label []byte `json:"label,omitempty"`
	// KeyVersion optionally names the key version to use; it must be
	// enabled. Zero chooses one; see transport.VerifyRequest.KeyVersion and
	// transport.DecryptRequest.KeyVersion.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// AsymmetricDecryptResult represents the result of asymmetric decryption
type AsymmetricDecryptResult struct {
	Plaintext []byte `json:"plaintext"`
	// KeyVersion is the key version that verified or decrypted.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// CopyKeyParams represents parameters for copying a key from one backend to
// another. It used to also carry KeyType, KeySize and Curve, which the
// service ignores outright: the copy takes its attributes from the source
// key. They were removed rather than left as dead input (go-xkms#1223).
type CopyKeyParams struct {
	SourceBackend string `json:"source_backend"` // Source backend name
	SourceKeyID   string `json:"source_key_id"`
	DestBackend   string `json:"dest_backend"` // Destination backend name
	DestKeyID     string `json:"dest_key_id"`
	Algorithm     string `json:"algorithm"` // Wrapping algorithm
	Hash          string `json:"hash,omitempty"`
	AESKeySize    int    `json:"aes_key_size,omitempty"`
	// TenantID is refused when set. Both ends of a copy are the authenticated
	// caller's own tenant; there are no cross-tenant copies on this transport.
	// See ErrTenantIDNotAccepted. The field exists so a caller that names a
	// tenant is told so rather than having it silently discarded.
	TenantID string `json:"tenant_id,omitempty"`
}

// CopyKeyResult represents the result of copying a key
type CopyKeyResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// SealParams represents parameters for sealing data
type SealParams struct {
	Backend string `json:"backend,omitempty"` // Backend to use for sealing (optional, uses default if not specified)
	KeyID   string `json:"key_id,omitempty"`  // Key ID to use for sealing (backend-specific)
	Data    []byte `json:"data"`              // Data to seal
	AAD     []byte `json:"aad,omitempty"`     // Additional Authenticated Data
	// Password is the TPM2 sealed object's authorization value. With a TPM
	// policy it counts only inside the policy; without one it is the
	// object's only protection.
	Password string `json:"password,omitempty"`
	// TPMPolicy names the TPM policy a TPM2 sealed object is bound to:
	// "platform", a named policy of the tenant's scope, or empty for none. A
	// TPM2 seal needs a policy, a password or both.
	TPMPolicy string `json:"tpm_policy,omitempty"`
}

// SealResult represents the result of sealing data
type SealResult struct {
	Backend    string            `json:"backend"`               // Backend that performed the sealing
	Ciphertext []byte            `json:"ciphertext"`            // Encrypted payload
	Nonce      []byte            `json:"nonce,omitempty"`       // IV/nonce used for encryption
	Tag        []byte            `json:"tag,omitempty"`         // Authentication tag for AEAD modes
	Metadata   map[string]string `json:"metadata,omitempty"`    // Backend-specific metadata
	KeyID      string            `json:"key_id,omitempty"`      // Key ID used for sealing
	WrappedDEK []byte            `json:"wrapped_dek,omitempty"` // Wrapped Data Encryption Key (envelope encryption)
	TPMPublic  []byte            `json:"tpm_public,omitempty"`  // TPM2 sealed object's public area
	TPMPrivate []byte            `json:"tpm_private,omitempty"` // TPM2 sealed object's private area
	KeyVersion uint32            `json:"key_version,omitempty"` // Sealing key version; pass it back on unseal
}

// UnsealParams represents parameters for unsealing data
type UnsealParams struct {
	Backend    string `json:"backend,omitempty"` // Backend to use for unsealing (optional, uses default if not specified)
	KeyID      string `json:"key_id,omitempty"`  // Key ID used for sealing
	Ciphertext []byte `json:"ciphertext"`        // Encrypted payload
	Nonce      []byte `json:"nonce,omitempty"`   // IV/nonce used for encryption
	Tag        []byte `json:"tag,omitempty"`     // Authentication tag for AEAD modes
	AAD        []byte `json:"aad,omitempty"`     // Additional Authenticated Data (must match sealing)
	// TPMPublic and TPMPrivate are a TPM2 sealed object's areas, given
	// instead of a ciphertext.
	TPMPublic  []byte `json:"tpm_public,omitempty"`
	TPMPrivate []byte `json:"tpm_private,omitempty"`
	// WrappedDEK is an envelope-sealing backend's wrapped key.
	WrappedDEK []byte `json:"wrapped_dek,omitempty"`
	// Metadata is the backend-specific data the seal returned.
	Metadata map[string][]byte `json:"metadata,omitempty"`
	// Password is the sealed object's authorization value (TPM2).
	Password string `json:"password,omitempty"`
	// KeyVersion is the sealing key version the seal reported. Zero tries
	// every enabled version, newest first.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// UnsealResult represents the result of unsealing data
type UnsealResult struct {
	Plaintext []byte `json:"plaintext"` // Decrypted data
}

// CanSealParams represents parameters for checking sealing capability
type CanSealParams struct {
	Backend string `json:"backend,omitempty"` // Backend to check (optional, checks default if not specified)
}

// CanSealResult represents the result of checking sealing capability
type CanSealResult struct {
	CanSeal bool `json:"can_seal"` // True if the backend supports sealing operations
}
