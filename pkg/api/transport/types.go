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

package transport

import (
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// HealthResponse contains health check information.
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
	Message string `json:"message,omitempty"`
}

// BackendCapabilities describes the operations a backend supports.
// Fields match the JSON tags from types.Capabilities on the server.
type BackendCapabilities struct {
	Keys                bool `json:"Keys"`
	HardwareBacked      bool `json:"HardwareBacked"`
	Signing             bool `json:"Signing"`
	Decryption          bool `json:"Decryption"`
	KeyRotation         bool `json:"KeyRotation"`
	SymmetricEncryption bool `json:"SymmetricEncryption"`
	Sealing             bool `json:"Sealing"`
	Import              bool `json:"Import"`
	Export              bool `json:"Export"`
	KeyAgreement        bool `json:"KeyAgreement"`
	ECIES               bool `json:"ECIES"`
	Attestation         bool `json:"Attestation"`
	QuantumSigning      bool `json:"QuantumSigning"`
	KeyEncapsulation    bool `json:"KeyEncapsulation"`
}

// BackendInfo contains information about a backend.
type BackendInfo struct {
	ID             string              `json:"id"`
	Type           string              `json:"type"`
	HardwareBacked bool                `json:"hardware_backed"`
	Capabilities   BackendCapabilities `json:"capabilities"`
}

// ListBackendsRequest contains pagination parameters for listing backends.
type ListBackendsRequest struct {
	PageRequest
}

// ListBackendsResponse contains a list of backends.
type ListBackendsResponse struct {
	Backends []BackendInfo `json:"backends"`
	PageResponse
}

// GenerateKeyRequest contains parameters for key generation.
type GenerateKeyRequest struct {
	KeyID      string `json:"key_id"`
	Backend    string `json:"backend"`
	KeyType    string `json:"key_type"`
	KeySize    int    `json:"key_size,omitempty"`
	Curve      string `json:"curve,omitempty"`
	Hash       string `json:"hash,omitempty"`
	Algorithm  string `json:"algorithm,omitempty"`
	Exportable bool   `json:"exportable,omitempty"`
	// Sensitive carries PKCS#11 CKA_SENSITIVE to the backend's key record so
	// the service layer, not the caller, decides whether the key's plaintext
	// may ever be released. It is independent of Exportable: a sensitive key
	// may still be wrapped out, but ExportKeyMaterial will refuse it.
	Sensitive bool `json:"sensitive,omitempty"`
	// Partition names the sub-namespace the key is stored in. It is part of
	// the key's identity (types.KeyAttributes.ID encodes it), so a request that
	// cannot express it cannot address a partitioned key at all. The gRPC
	// GenerateKeyRequest message has always carried a partition field, which
	// this struct could not represent.
	Partition string `json:"partition,omitempty"`
	// TPMPolicy names the TPM policy of the tenant's scope a TPM2 key is
	// bound to. Empty binds it to the built-in "platform" policy; any other
	// backend refuses a non-empty value.
	TPMPolicy string `json:"tpm_policy,omitempty"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// GenerateKeyResponse contains the result of key generation.
type GenerateKeyResponse struct {
	KeyID        string `json:"key_id"`
	KeyType      string `json:"key_type"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	Message      string `json:"message,omitempty"`
}

// KeyInfo contains information about a key.
type KeyInfo struct {
	KeyID        string `json:"key_id"`
	KeyType      string `json:"key_type"`
	Algorithm    string `json:"algorithm,omitempty"`
	Backend      string `json:"backend"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	// KeySize is the RSA modulus size in bits; zero for any other key.
	KeySize int `json:"key_size,omitempty"`
	// Curve names an ECDSA key's curve ("P-256"); empty for any other key.
	Curve string `json:"curve,omitempty"`
	// Partition is the key's storage partition, when it has one.
	Partition string `json:"partition,omitempty"`
	// KeyVersion is the key's current version, the one sign and encrypt use.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// ListKeysRequest contains parameters for listing keys.
type ListKeysRequest struct {
	Backend string `json:"backend"`
	PageRequest
}

// ListKeysResponse contains a list of keys.
type ListKeysResponse struct {
	Keys []KeyInfo `json:"keys"`
	PageResponse
}

// GetKeyResponse contains key information.
type GetKeyResponse struct {
	KeyInfo
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
}

// DeleteKeyResponse contains the result of key deletion.
type DeleteKeyResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// SignRequest contains parameters for signing.
type SignRequest struct {
	Backend string `json:"backend"`
	KeyID   string `json:"key_id"`
	Data    []byte `json:"data"`
	// Hash names the digest algorithm to apply to Data before signing.
	// Empty selects the SHA-256 default. The sentinel value "NONE" means
	// Data is already a complete digest (e.g. a caller-built DigestInfo, as
	// PKCS#11's raw CKM_RSA_PKCS mechanism requires) and must be signed
	// as-is, with no hashing applied.
	Hash string `json:"hash,omitempty"`
	// DataIsDigest states that Data is already the digest and must not be
	// hashed again, while leaving Hash to name which digest produced it.
	//
	// Hash alone conflates two independent questions -- which hash function,
	// and whether to apply it -- and the sentinel "NONE" can only answer both
	// at once, by declaring that no hash function is involved at all. That is
	// exactly right for PKCS#11's raw CKM_RSA_PKCS and CKM_ECDSA, where the
	// signature scheme itself needs no digest identity. It cannot express
	// RSASSA-PSS: PKCS#11 v3.2 section 6.1.15 defines the input to
	// CKM_RSA_PKCS_PSS as already hashed, yet the scheme still needs the
	// digest's identity for MGF1 and the salt length (RFC 8017 section 9.1).
	// Naming the hash was therefore taken as an instruction to apply it, and
	// the digest the caller supplied got hashed a second time, producing
	// signatures that verified only against this implementation.
	//
	// It is an error to set DataIsDigest without also naming Hash unless the
	// scheme genuinely has no digest identity, in which case Hash is "NONE".
	DataIsDigest bool `json:"data_is_digest,omitempty"`
	// Padding selects the RSA signature padding scheme: "" or "pkcs1v15"
	// (default, PKCS#1 v1.5) or "pss" (RSASSA-PSS). Only meaningful for RSA
	// keys; a non-default value on an ECDSA or Ed25519 key is rejected.
	Padding string `json:"padding,omitempty"`
	// SaltLength is the RSA-PSS salt length in bytes. Zero selects
	// rsa.PSSSaltLengthAuto (the largest salt that fits the modulus).
	// A literal zero-byte salt cannot be requested: crypto/rsa has no encoding
	// for it, so the PKCS#11 layer refuses CK_RSA_PKCS_PSS_PARAMS.sLen of 0
	// rather than silently signing under "auto".
	// Ignored unless Padding is "pss".
	SaltLength int `json:"salt_length,omitempty"`
	// PreHash selects the pre-hashed EdDSA variant (Ed25519ph / Ed448ph)
	// per RFC 8032 Table 73. Only meaningful for Ed25519/Ed448 keys signed
	// under CKM_EDDSA with a CK_EDDSA_PARAMS.phFlag of CK_TRUE; ignored
	// for every other key algorithm.
	PreHash bool `json:"pre_hash,omitempty"`
	// Context is the optional EdDSA context string (CK_EDDSA_PARAMS.
	// pContextData), 0-255 bytes, shared between signer and verifier.
	// Selects Ed25519ctx/Ed25519ph when non-empty or when PreHash is set;
	// ignored for every non-EdDSA key algorithm.
	Context []byte `json:"context,omitempty"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// SignResponse contains the signature.
type SignResponse struct {
	Signature []byte `json:"signature"`
	Algorithm string `json:"algorithm,omitempty"`
	// KeyVersion is the key version that produced the signature: always the
	// current one. It is metadata beside the signature, never inside it.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// VerifyRequest contains parameters for signature verification.
type VerifyRequest struct {
	Backend   string `json:"backend"`
	KeyID     string `json:"key_id"`
	Data      []byte `json:"data"`
	Signature []byte `json:"signature"`
	// Hash names the digest algorithm applied to Data before verification.
	// Empty selects the SHA-256 default. The sentinel value "NONE" means
	// Data is already a complete digest and must be verified as-is, with no
	// hashing applied (PKCS#11's raw CKM_RSA_PKCS contract).
	Hash string `json:"hash,omitempty"`
	// DataIsDigest states that Data is already the digest and must not be
	// hashed again, while Hash still names which digest produced it. It must
	// match the value used to produce Signature. See SignRequest.DataIsDigest
	// for why the two are separate fields.
	DataIsDigest bool `json:"data_is_digest,omitempty"`
	// Padding selects the RSA signature padding scheme: "" or "pkcs1v15"
	// (default, PKCS#1 v1.5) or "pss" (RSASSA-PSS). Only meaningful for RSA
	// keys; a non-default value on an ECDSA or Ed25519 key is rejected.
	Padding string `json:"padding,omitempty"`
	// SaltLength is the RSA-PSS salt length in bytes the signature is
	// expected to use. Zero selects rsa.PSSSaltLengthAuto, which accepts a
	// signature carrying ANY salt length. A verifier that must require an exact
	// length has to name it positively; see SignRequest.SaltLength.
	// Ignored unless Padding is "pss".
	SaltLength int `json:"salt_length,omitempty"`
	// PreHash selects the pre-hashed EdDSA variant (Ed25519ph / Ed448ph)
	// per RFC 8032 Table 73. See SignRequest.PreHash.
	PreHash bool `json:"pre_hash,omitempty"`
	// Context is the optional EdDSA context string (CK_EDDSA_PARAMS.
	// pContextData). See SignRequest.Context.
	Context []byte `json:"context,omitempty"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
	// KeyVersion optionally names the key version to verify with; it must be
	// enabled. Zero tries every enabled version, newest first.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// VerifyResponse contains the verification result.
type VerifyResponse struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message,omitempty"`
	// KeyVersion is the key version the signature verified under; zero when
	// it did not verify.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// EncryptRequest contains parameters for encryption.
type EncryptRequest struct {
	Backend        string `json:"backend"`
	KeyID          string `json:"key_id"`
	Plaintext      []byte `json:"plaintext"`
	AdditionalData []byte `json:"additional_data,omitempty"`
	// Nonce optionally supplies the IV/nonce to use for this encryption. If
	// nil or empty, a random nonce is generated by the backend's configured
	// RNG (the existing behavior) and returned in EncryptResponse.Nonce.
	// When supplied, its length must match the cipher's nonce size (12 bytes
	// for AES-GCM; 12 or 24 bytes for ChaCha20-Poly1305/XChaCha20-Poly1305).
	// Only meaningful for the default AEAD Mode; AES-CBC uses IV instead.
	Nonce []byte `json:"nonce,omitempty"`
	// Mode selects the symmetric cipher mode of operation: "" (default)
	// selects the key's native AEAD mode (AES-GCM or
	// ChaCha20-Poly1305/XChaCha20-Poly1305); "cbc" selects unpadded AES-CBC
	// (PKCS#11's CKM_AES_CBC -- Plaintext must already be a whole number of
	// AES blocks); "cbc-pad" selects AES-CBC with PKCS#7 padding (PKCS#11's
	// CKM_AES_CBC_PAD, RFC 5652 section 6.3). CBC modes require an AES key
	// and reject AdditionalData (AES-CBC has no authenticated-data input).
	Mode string `json:"mode,omitempty"`
	// IV supplies the AES-CBC initialization vector, exactly 16 bytes (the
	// AES block size). Ignored for the default AEAD modes, which use Nonce
	// instead. Unlike Nonce, an IV carries no authentication role -- CBC's
	// confidentiality only requires it be unpredictable, not secret -- but
	// reuse still leaks equal-prefix plaintext information across messages.
	// If empty on encrypt with a CBC Mode, a random IV is generated and
	// returned in EncryptResponse.IV.
	IV []byte `json:"iv,omitempty"`
	// TagSize is the AEAD authentication tag length in bytes. Zero selects
	// the cipher's full-length tag, which is the only length NIST SP 800-38D
	// appendix C recommends without a supporting analysis.
	//
	// SP 800-38D section 5.2.1.2 defines a t-bit tag as the leading t bits of
	// the full 128-bit GCM tag, so AES-GCM admits 12, 13, 14, 15 and 16 bytes
	// (96, 104, 112, 120 and 128 bits). Poly1305 has no such construction and
	// accepts only its full 16-byte tag. A backend that cannot produce the
	// requested length must refuse rather than substitute one: a caller that
	// asked for a short tag and got a long one, or the reverse, has a
	// ciphertext its peer cannot authenticate.
	TagSize int `json:"tag_size,omitempty"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// EncryptResponse contains the encrypted data.
type EncryptResponse struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce,omitempty"`
	Tag        []byte `json:"tag,omitempty"`
	// IV is the AES-CBC initialization vector used for encryption. Populated
	// when the request's Mode was "cbc" or "cbc-pad"; empty for the default
	// AEAD modes, which populate Nonce instead. Required (unchanged) on the
	// matching DecryptRequest.
	IV []byte `json:"iv,omitempty"`
	// GCMNonceMode mirrors types.EncryptedData.GCMNonceMode: "" (the zero
	// value) for a caller- or RNG-supplied nonce Seal took as a parameter,
	// or "random" when GODEBUG=fips140=only forced this encryption through
	// cipher.NewGCMWithRandomNonce (see docs/fips/README.md "AEAD
	// construction"). A caller must echo this value back unchanged on the
	// matching DecryptRequest -- Decrypt needs it to rebuild the same AEAD
	// construction Encrypt used, and cannot infer it from the ciphertext
	// bytes alone. Empty for CBC and for algorithms with only one
	// construction (ChaCha20-Poly1305/XChaCha20-Poly1305).
	GCMNonceMode string `json:"gcm_nonce_mode,omitempty"`
	// KeyVersion is the key version that produced the ciphertext: always the
	// current one. Keep it: AES-CBC ciphertext cannot be decrypted without
	// it once the key has more than one enabled version.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// DecryptRequest contains parameters for decryption.
type DecryptRequest struct {
	Backend        string `json:"backend"`
	KeyID          string `json:"key_id"`
	Ciphertext     []byte `json:"ciphertext"`
	Nonce          []byte `json:"nonce,omitempty"`
	Tag            []byte `json:"tag,omitempty"`
	AdditionalData []byte `json:"additional_data,omitempty"`
	// GCMNonceMode is the value the matching EncryptResponse.GCMNonceMode
	// reported; see its doc comment. Required, unchanged, to decrypt an
	// AES-GCM ciphertext produced under GODEBUG=fips140=only -- omitting it
	// reconstructs the wrong AEAD construction and Decrypt fails closed.
	GCMNonceMode string `json:"gcm_nonce_mode,omitempty"`
	// Mode selects the symmetric cipher mode of operation. See
	// EncryptRequest.Mode; must match the Mode used to produce Ciphertext.
	// Ignored for asymmetric (RSA) decryption, which uses Padding/Hash/Label
	// below instead.
	Mode string `json:"mode,omitempty"`
	// IV is the AES-CBC initialization vector used at encryption time,
	// exactly 16 bytes. Required when Mode is "cbc" or "cbc-pad"; ignored
	// for the default AEAD modes, which use Nonce instead.
	IV []byte `json:"iv,omitempty"`
	// Padding selects the RSA decryption scheme for an asymmetric key:
	// "" or "pkcs1v15" (default), or "oaep".
	Padding string `json:"padding,omitempty"`
	// Hash names the OAEP digest (e.g. "SHA-256"). Ignored unless Padding is
	// "oaep"; an empty value selects SHA-1, which is OAEP's own default.
	Hash string `json:"hash,omitempty"`
	// Label is the optional OAEP label. Ignored unless Padding is "oaep".
	Label []byte `json:"label,omitempty"`
	// TagSize is the AEAD authentication tag length in bytes that Tag
	// carries. Zero selects the cipher's full-length tag. It must equal the
	// TagSize the matching EncryptRequest used: a truncated tag has to be
	// verified against a tag recomputed at the same length (NIST SP 800-38D
	// section 5.2.2, step 5), so a decrypt that assumes the full length
	// rejects every short tag as a forgery.
	TagSize int `json:"tag_size,omitempty"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
	// KeyVersion optionally names the key version to decrypt with; it must be
	// enabled. Zero tries every enabled version, newest first, for AEAD and
	// RSA-OAEP ciphertext, and requires exactly one enabled version for
	// AES-CBC and RSA PKCS#1 v1.5 ciphertext.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// DecryptResponse contains the decrypted data.
type DecryptResponse struct {
	Plaintext []byte `json:"plaintext"`
	// KeyVersion is the key version that decrypted the ciphertext.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// EncryptAsymRequest contains parameters for asymmetric encryption.
type EncryptAsymRequest struct {
	Backend   string `json:"backend"`
	KeyID     string `json:"key_id"`
	Plaintext []byte `json:"plaintext"`
	Hash      string `json:"hash,omitempty"`
	// Label is the optional OAEP label, RFC 8017's encoding parameter L. It
	// must match the Label the matching DecryptRequest carries, or the
	// decryption fails as though the ciphertext were corrupt.
	//
	// It exists because the field's absence was silent: PKCS#11 callers set
	// CK_RSA_PKCS_OAEP_PARAMS.pSourceData, the module parsed it, and this
	// request had nowhere to put it, so every encryption ran under the empty
	// label while the matching decryption sent the caller's. The round trip
	// could not close, and against an external peer the ciphertext was simply
	// undecryptable, with nothing anywhere reporting the substitution.
	Label []byte `json:"label,omitempty"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// EncryptAsymResponse contains the encrypted data from asymmetric encryption.
type EncryptAsymResponse struct {
	Ciphertext []byte `json:"ciphertext"`
	// KeyVersion is the key version whose public key produced the
	// ciphertext: always the current one.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// SealRequest contains parameters for sealing data.
type SealRequest struct {
	Backend string `json:"backend"`
	KeyID   string `json:"key_id"`
	Data    []byte `json:"data"`
	AAD     []byte `json:"aad,omitempty"` // Additional Authenticated Data
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`

	// TPMPolicy names the TPM policy a TPM2 sealed object is bound to (TPM2
	// backends only; any other backend refuses it): "platform", a named
	// policy of the tenant's scope, or empty for none. A TPM2 seal needs a
	// policy, a password or both; one with neither is refused
	// (tpm2.ErrSealUnprotected).
	TPMPolicy string `json:"tpm_policy,omitempty"`

	// Password is the TPM2 sealed object's authorization value. With a TPM
	// policy it counts only inside the policy; without one it is the
	// object's only protection.
	//
	// It is a types.SecretBytes so it never becomes an unwipeable string; the
	// producer and the consumer each wipe it. The JSON form is unchanged.
	Password types.SecretBytes `json:"password,omitempty"`
}

// SealResponse contains the sealed data.
type SealResponse struct {
	Backend    string `json:"backend"`
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce,omitempty"`
	Tag        []byte `json:"tag,omitempty"`

	// TPMPublic contains the TPM public area for sealed objects.
	// Only populated by TPM2 backend.
	TPMPublic []byte `json:"tpm_public,omitempty"`

	// TPMPrivate contains the TPM private area (encrypted) for sealed objects.
	// Only populated by TPM2 backend.
	TPMPrivate []byte `json:"tpm_private,omitempty"`

	// WrappedDEK contains a wrapped Data Encryption Key (for envelope encryption).
	// Used by cloud KMS backends (AWS, Azure, GCP).
	WrappedDEK []byte `json:"wrapped_dek,omitempty"`

	// KeyID identifies the key that performed the sealing.
	// Format is backend-specific (e.g., ARN for AWS, key path for GCP).
	KeyID string `json:"key_id,omitempty"`

	// Metadata contains additional backend-specific data.
	// Keys should be namespaced (e.g., "tpm:creation_ticket", "aws:encryption_context").
	Metadata map[string][]byte `json:"metadata,omitempty"`

	// KeyVersion is the version of the sealing key that sealed the data;
	// zero for a TPM2 sealed object, which is its own object and has no
	// versions. Pass it back on Unseal.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// UnsealRequest contains parameters for unsealing data.
type UnsealRequest struct {
	Backend    string `json:"backend"`
	KeyID      string `json:"key_id"`
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce,omitempty"`
	Tag        []byte `json:"tag,omitempty"`
	AAD        []byte `json:"aad,omitempty"` // Additional Authenticated Data
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`

	// TPMPublic contains the TPM public area for sealed objects.
	// Required for TPM2 backend unseal operations.
	TPMPublic []byte `json:"tpm_public,omitempty"`

	// TPMPrivate contains the TPM private area (encrypted) for sealed objects.
	// Required for TPM2 backend unseal operations.
	TPMPrivate []byte `json:"tpm_private,omitempty"`

	// WrappedDEK contains a wrapped Data Encryption Key (for envelope encryption).
	// Required for cloud KMS backends that use envelope encryption.
	WrappedDEK []byte `json:"wrapped_dek,omitempty"`

	// Metadata contains additional backend-specific data.
	Metadata map[string][]byte `json:"metadata,omitempty"`

	// Password provides authentication for the sealed object (TPM-specific).
	// This is the UserAuth value required to unseal.
	// It is a types.SecretBytes; see SealRequest.Password.
	Password types.SecretBytes `json:"password,omitempty"`

	// KeyVersion is the sealing key version SealResponse.KeyVersion
	// reported. Zero tries every enabled version, newest first.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// UnsealResponse contains the unsealed data.
type UnsealResponse struct {
	Plaintext []byte `json:"plaintext"`
}

// CanSealResponse indicates whether the backend supports sealing operations.
type CanSealResponse struct {
	CanSeal bool   `json:"can_seal"`
	Backend string `json:"backend"`
	Message string `json:"message,omitempty"`
}

// AttestKeyRequest contains parameters for requesting key attestation.
// Attestation proves that a key was created in hardware (TPM2, Android TEE/StrongBox, etc.)
// and never left the secure boundary.
type AttestKeyRequest struct {
	Backend string `json:"backend"`
	KeyID   string `json:"key_id"`
	Nonce   []byte `json:"nonce"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// AttestKeyResponse contains the attestation statement from the backend.
// The response includes cryptographic evidence that the key resides in hardware.
type AttestKeyResponse struct {
	Format             string   `json:"format"`
	CertificateChain   [][]byte `json:"certificate_chain"`
	AttestationData    []byte   `json:"attestation_data"`
	Signature          []byte   `json:"signature"`
	SignatureAlgorithm string   `json:"signature_algorithm,omitempty"`
	Nonce              []byte   `json:"nonce"`
	Backend            string   `json:"backend"`
}

// GetCertificateResponse contains a certificate.
type GetCertificateResponse struct {
	KeyID          string `json:"key_id"`
	CertificatePEM string `json:"certificate_pem"`
}

// SaveCertificateRequest contains parameters for saving a certificate.
type SaveCertificateRequest struct {
	Backend        string `json:"backend"`
	KeyID          string `json:"key_id"`
	CertificatePEM string `json:"certificate_pem"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// ImportKeyRequest contains parameters for importing a key.
// Uses BYOK (Bring Your Own Key) protocol: the key material must be wrapped
// using the wrapping key and import token obtained from GetImportParameters.
// KeyType names the ALGORITHM of the key being imported -- "rsa", "ecdsa",
// "ed25519", "symmetric" or "aes" -- not the key's purpose. Algorithm below is
// already taken by the wrapping algorithm, so this is the only field that can
// carry it, and the service derives the purpose from it.
type ImportKeyRequest struct {
	Backend            string `json:"backend"`
	KeyID              string `json:"key_id"`
	KeyType            string `json:"key_type,omitempty"`
	KeySize            int    `json:"key_size,omitempty"`
	Curve              string `json:"curve,omitempty"`
	Hash               string `json:"hash,omitempty"`
	AESKeySize         int    `json:"aes_key_size,omitempty"`
	WrappedKeyMaterial []byte `json:"wrapped_key_material"`
	Algorithm          string `json:"algorithm"`
	ImportToken        []byte `json:"import_token,omitempty"`
	// Partition names the sub-namespace the imported key is stored in, as it
	// does for GenerateKeyRequest.
	Partition string `json:"partition,omitempty"`
	// Metadata carries backend-specific information about the wrapped key
	// (key usage flags, provenance, and so on) through to the backend's
	// ImportKey. The gRPC ImportKeyRequest message has always carried it; this
	// struct could not represent it, so every transport routed through here
	// silently dropped it.
	Metadata map[string]string `json:"metadata,omitempty"`
	// Exportable records whether the imported key may leave the backend
	// again, wrapped or as raw material. Unset means the write-once default
	// the backend applies: true for symmetric material (PKCS#11 v3.2 Table 30
	// makes a secret key CKA_EXTRACTABLE by default, and a symmetric key the
	// backend will not release can neither be read back nor wrapped), false
	// for asymmetric material, as GenerateKeyRequest's zero value is. It is a
	// pointer because the default is true and a plain bool cannot say
	// "unset"; an explicit false imports non-extractable secret material,
	// which no transport could express before.
	Exportable *bool `json:"exportable,omitempty"`
	// Sensitive carries PKCS#11 CKA_SENSITIVE to the backend's key record, as
	// GenerateKeyRequest does: the key's plaintext may never be released. It is
	// independent of Exportable; a sensitive key may still be wrapped out, but
	// ExportKeyMaterial refuses it.
	Sensitive bool `json:"sensitive,omitempty"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// ImportKeyResponse contains the result of key import.
type ImportKeyResponse struct {
	Success      bool   `json:"success"`
	KeyID        string `json:"key_id"`
	Message      string `json:"message,omitempty"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
}

// ExportKeyRequest contains parameters for exporting a key.
type ExportKeyRequest struct {
	Backend   string `json:"backend"`
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// ExportKeyResponse contains the exported key.
type ExportKeyResponse struct {
	KeyID              string `json:"key_id"`
	WrappedKeyMaterial []byte `json:"wrapped_key_material"`
	Algorithm          string `json:"algorithm"`
	// ImportToken names the wrapping key the material was wrapped under, as
	// the exporting backend minted it. The backend selects the unwrapping
	// private key by this token, so a response that drops it hands the caller
	// material no ImportKey can open.
	ImportToken []byte `json:"import_token,omitempty"`
	// Metadata is the exporting backend's own description of the wrapped
	// material. It travels with the blob to ImportKey.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// RotateKeyRequest contains parameters for key rotation.
type RotateKeyRequest struct {
	Backend string `json:"backend"`
	KeyID   string `json:"key_id"`
	KeyType string `json:"key_type,omitempty"`
	KeySize int    `json:"key_size,omitempty"`
	Curve   string `json:"curve,omitempty"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// OTAImageKeyRequest names the OTA image-signing key of one trusted-firmware
// board, to create or rotate.
type OTAImageKeyRequest struct {
	Backend string `json:"backend"`
	BoardID string `json:"board_id"`
	// Algorithm must be ES256; empty selects it.
	Algorithm string `json:"algorithm,omitempty"`
	// TenantID optionally scopes the key to a tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// OTAImageSignRequest signs an OTA image, or its SHA-256 digest, with the
// current version of a board's OTA image-signing key.
type OTAImageSignRequest struct {
	Backend string `json:"backend"`
	BoardID string `json:"board_id"`
	Data    []byte `json:"data"`
	// DataIsDigest states that Data is already the image's SHA-256 digest.
	DataIsDigest bool `json:"data_is_digest,omitempty"`
	// TenantID optionally scopes the key to a tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// ExportOTAImageKeyResponse is the public half of a board's OTA
// image-signing key and the record of which board id its key ID belongs to.
// It never carries private key material.
type ExportOTAImageKeyResponse struct {
	BoardID string `json:"board_id"`
	KeyID   string `json:"key_id"`
	// KeyVersion is the exported version: always the current one, the one
	// SignOTAImage signs with and names in SignResponse.KeyVersion.
	KeyVersion uint32 `json:"key_version"`
	// Algorithm is always ES256.
	Algorithm string `json:"algorithm"`
	// PublicKey is the raw 64-byte X || Y, each coordinate 32 bytes
	// big-endian, left-padded.
	PublicKey []byte `json:"public_key"`
	// COSEKey is the RFC 9052 §7 COSE_Key (RFC 9053 §7.1.1 EC2, kid the
	// key ID, alg ES256) in RFC 8949 §4.2.1 deterministic CBOR.
	COSEKey []byte `json:"cose_key"`
}

// RotateKeyResponse contains the result of key rotation.
type RotateKeyResponse struct {
	Success bool   `json:"success"`
	KeyID   string `json:"key_id"`
	// KeyType is the rotated key's type ("SIGNING", "ENCRYPTION", ...),
	// which rotation preserves.
	KeyType      string `json:"key_type,omitempty"`
	Message      string `json:"message,omitempty"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	// KeyVersion is the version the rotation created, now current.
	KeyVersion uint32 `json:"key_version,omitempty"`
	// CertificateReissueRequired reports that the key has a certificate,
	// which still certifies the previous version: issue a new one for the
	// new version.
	CertificateReissueRequired bool `json:"certificate_reissue_required,omitempty"`
}

// GetImportParametersRequest contains parameters for getting import parameters.
type GetImportParametersRequest struct {
	Backend   string `json:"backend"`
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	KeyType   string `json:"key_type,omitempty"`
	KeySize   int    `json:"key_size,omitempty"`
	Curve     string `json:"curve,omitempty"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// GetImportParametersResponse contains the import parameters.
type GetImportParametersResponse struct {
	WrappingPublicKey []byte `json:"wrapping_public_key"`
	ImportToken       []byte `json:"import_token,omitempty"`
	Algorithm         string `json:"algorithm"`
	ExpiresAt         string `json:"expires_at,omitempty"`
	// KeySpec describes the kind of key these parameters accept, as the
	// backend named it ("RSA_2048", "AES_256", "ECC_NIST_P256"). An
	// AWS-KMS-style ceremony carries it back into WrapKey, so a response that
	// omits it forces the caller to guess.
	KeySpec string `json:"key_spec,omitempty"`
}

// WrapKeyRequest contains parameters for wrapping a key.
type WrapKeyRequest struct {
	Backend           string `json:"backend"`
	KeyMaterial       []byte `json:"key_material"`
	Algorithm         string `json:"algorithm"`
	WrappingPublicKey []byte `json:"wrapping_public_key,omitempty"`
	ImportToken       []byte `json:"import_token,omitempty"`
	// KeySpec is the key spec from GetImportParametersResponse. Backends whose
	// import ceremony is key-spec aware -- AWS KMS most visibly -- need it back
	// to wrap for the right target key kind.
	KeySpec string `json:"key_spec,omitempty"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// WrapKeyResponse contains the wrapped key.
type WrapKeyResponse struct {
	WrappedKeyMaterial []byte `json:"wrapped_key_material"`
	Algorithm          string `json:"algorithm"`
	// ImportToken is the token the material was wrapped for, echoed by
	// backends that bind the wrap to a ceremony. ImportKey selects the
	// unwrapping key by it, so it travels with the blob.
	ImportToken []byte `json:"import_token,omitempty"`
	// Metadata is the backend's own description of the wrapped material. It
	// travels with the blob to ImportKey, so dropping it here loses whatever
	// the wrapping backend recorded about the key.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// UnwrapKeyRequest contains parameters for unwrapping a key.
type UnwrapKeyRequest struct {
	Backend            string `json:"backend"`
	WrappedKeyMaterial []byte `json:"wrapped_key_material"`
	Algorithm          string `json:"algorithm"`
	ImportToken        []byte `json:"import_token,omitempty"`
	// WrappingPublicKey is the DER-encoded PKIX public key the material was
	// wrapped under. Backends that hold more than one wrapping key pair at a
	// time use it to select the matching private key.
	WrappingPublicKey []byte `json:"wrapping_public_key,omitempty"`
	// KeySpec is the key spec the material was wrapped for, as returned by
	// GetImportParameters.
	KeySpec string `json:"key_spec,omitempty"`
	// Metadata is the backend-specific description that accompanied the
	// wrapped material, as returned by WrapKeyResponse.
	Metadata map[string]string `json:"metadata,omitempty"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// UnwrapKeyResponse contains the unwrapped key.
type UnwrapKeyResponse struct {
	KeyMaterial []byte `json:"key_material"`
}

// CopyKeyRequest contains parameters for copying a key.
//
// It names the source key, the destination, and the wrapping algorithm, and
// nothing about the key itself: the copy takes its algorithm, size, curve,
// hash and partition from the source key (XKMSService.CopyKey). It used to
// also carry KeyType, KeySize and Curve, which the service ignored outright;
// they were removed rather than left as dead input every transport had to
// keep threading through (go-xkms#1223).
type CopyKeyRequest struct {
	SourceBackend string `json:"source_backend"`
	SourceKeyID   string `json:"source_key_id"`
	DestBackend   string `json:"dest_backend"`
	DestKeyID     string `json:"dest_key_id"`
	Algorithm     string `json:"algorithm"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// CopyKeyResponse contains the result of key copy.
type CopyKeyResponse struct {
	Success      bool   `json:"success"`
	KeyID        string `json:"key_id"`
	Message      string `json:"message,omitempty"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
}

// CertificateInfo contains information about a certificate.
type CertificateInfo struct {
	KeyID          string `json:"key_id"`
	Subject        string `json:"subject,omitempty"`
	Issuer         string `json:"issuer,omitempty"`
	NotBefore      string `json:"not_before,omitempty"`
	NotAfter       string `json:"not_after,omitempty"`
	SerialNumber   string `json:"serial_number,omitempty"`
	CertificatePEM string `json:"certificate_pem,omitempty"`
}

// ListCertificatesRequest contains parameters for listing certificates.
type ListCertificatesRequest struct {
	Backend string `json:"backend"`
	PageRequest
}

// ListCertificatesResponse contains a list of certificates.
type ListCertificatesResponse struct {
	Certificates []CertificateInfo `json:"certificates"`
	PageResponse
}

// SaveCertificateChainRequest contains parameters for saving a certificate chain.
type SaveCertificateChainRequest struct {
	Backend  string   `json:"backend"`
	KeyID    string   `json:"key_id"`
	ChainPEM []string `json:"chain_pem"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// GetCertificateChainResponse contains a certificate chain.
type GetCertificateChainResponse struct {
	KeyID    string   `json:"key_id"`
	ChainPEM []string `json:"chain_pem"`
}

// GetTLSCertificateResponse contains a TLS certificate and its chain. It is
// the one canonical response shape returned by every transport (REST, gRPC,
// unix, QUIC, MCP, embedded) for GetTLSCertificate; no transport defines its
// own variant. ChainPEM holds one PEM-encoded certificate per chain entry,
// leaf excluded. The private key is never included: it stays in the backend
// that holds it (go-xkms#627).
type GetTLSCertificateResponse struct {
	KeyID          string   `json:"key_id"`
	CertificatePEM string   `json:"certificate_pem"`
	ChainPEM       []string `json:"chain_pem,omitempty"`
}

// UserInfo contains information about an xkms user. xkms presents its own
// user model; the backing store is the embedded qrdb node.
type UserInfo struct {
	// ID is the numeric identifier assigned by the embedded qrdb node. It is
	// marshalled as a string, matching qrdb's own User DTO: a uint64 exceeds
	// the range JSON numbers represent exactly, so a JavaScript client would
	// silently round large ids. The N-factor endpoints are keyed by this id.
	ID       uint64 `json:"id,string"`
	Username string `json:"username"`
	// Email is the canonical tenant-unique login key. It is projected on every
	// read: without it a caller can create a user with a login key and never
	// see it again, which is how the display name went missing too.
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	// Roles names every role the user holds, in the order qrdb stores them.
	Roles     []string   `json:"roles,omitempty"`
	Enabled   bool       `json:"enabled"`
	CreatedAt time.Time  `json:"created_at"`
	LastLogin *time.Time `json:"last_login,omitempty"`
}

// CredentialInfo contains information about a user credential.
type CredentialInfo struct {
	ID          string     `json:"id"`
	DisplayName string     `json:"display_name,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsed    *time.Time `json:"last_used,omitempty"`
}

// CreateUserRequest contains parameters to create a new xkms user.
type CreateUserRequest struct {
	Username string `json:"username"`
	// Email is the canonical tenant-unique login key (go-qrdb #190) and is
	// REQUIRED. xkms resolves logins and WebAuthn enrollment through it, so a
	// user created without one exists and cannot authenticate. It is a distinct
	// field rather than an email-shaped Username: inferring one from the other
	// is what put usernames and emails in the same slot to begin with.
	Email string `json:"email"`
	// WithoutEmailLoginKey DECLARES that this user intentionally has no email
	// login key — the certificate-authenticated admin path, which resolves by
	// SPKI thumbprint rather than by email. Mirrors qrdb's field of the same
	// name: the absence of a login key must be stated, never defaulted.
	WithoutEmailLoginKey bool   `json:"without_email_login_key,omitempty"`
	DisplayName          string `json:"display_name,omitempty"`
	Role                 string `json:"role,omitempty"`
	TenantID             string `json:"tenant_id,omitempty"`
	// InviteTTLSeconds overrides how long the minted invitation stays
	// redeemable (go-xkms#1294 part B). Zero or negative takes the server's
	// configured default; a value above the server's configured cap is
	// clamped down to it, never refused. Ignored when WithoutEmailLoginKey
	// is set: a bootstrap/certificate-only identity has no email an
	// invitation could be sent to and is created active, as before.
	InviteTTLSeconds int64 `json:"invite_ttl_seconds,omitempty"`
}

// InviteInfo is the one-time activation invitation CreateUser mints for a
// new account (go-xkms#1294 part B). Token is the plaintext token: it is
// returned exactly once, here, and cannot be recovered afterwards — only its
// digest is stored — so a caller that loses it must delete and recreate the
// user, or use xkmsctl's invite-reissue path once one exists.
type InviteInfo struct {
	Token     string    `json:"token"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ListUsersRequest contains pagination parameters for listing users.
type ListUsersRequest struct {
	PageRequest
}

// ListUsersResponse contains a list of users.
type ListUsersResponse struct {
	Users []UserInfo `json:"users"`
	PageResponse
}

// GetUserResponse contains user information. Invite is set only by
// CreateUser's response, for an account created with an email login key
// (go-xkms#1294 part B); every other caller of GetUserResponse (GetUser,
// UpdateUser) leaves it nil, since the plaintext token is not recoverable
// after creation.
type GetUserResponse struct {
	User   UserInfo    `json:"user"`
	Invite *InviteInfo `json:"invite,omitempty"`
}

// ListUserCredentialsRequest contains parameters for listing user credentials.
type ListUserCredentialsRequest struct {
	Username string `json:"username"`
	PageRequest
}

// ListUserCredentialsResponse contains a list of user credentials.
type ListUserCredentialsResponse struct {
	Credentials []CredentialInfo `json:"credentials"`
	PageResponse
}

// Authentication flow types for FIDO2/WebAuthn server-side operations.
//
// The registration ceremony is lossless: BeginRegistration returns the full
// JSON-marshaled WebAuthn options (CredentialCreation) and an opaque session
// ID, and FinishRegistration carries the full WebAuthn PublicKeyCredential
// attestation JSON back to the server. This mirrors the browser ceremony
// served by pkg/webauthn/http exactly, just transported over the SDK.

// BeginRegistrationRequest contains parameters to begin a WebAuthn registration.
type BeginRegistrationRequest struct {
	// Email is the canonical tenant-unique login key of the account the
	// credential is enrolled against. The service resolves the account with
	// GetByEmail; a username is a different identifier and is not accepted.
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

// BeginRegistrationResponse carries the session ID and the JSON-marshaled
// WebAuthn registration options produced by the relying party.
type BeginRegistrationResponse struct {
	// SessionID is the opaque server-side session identifier that must be
	// echoed back to FinishRegistration to correlate the ceremony.
	SessionID string `json:"session_id"`

	// OptionsJSON is the JSON-marshaled *protocol.CredentialCreation
	// (PublicKeyCredentialCreationOptions) that the client hands to the
	// authenticator via navigator.credentials.create().
	OptionsJSON string `json:"options_json"`
}

// FinishRegistrationRequest carries the authenticator attestation back to the
// server to complete the registration ceremony.
type FinishRegistrationRequest struct {
	// SessionID is the value returned by BeginRegistration.
	SessionID string `json:"session_id"`

	// AttestationJSON is the WebAuthn PublicKeyCredential JSON produced by the
	// authenticator (the response from navigator.credentials.create()). It is
	// the exact body that protocol.ParseCredentialCreationResponseBody expects.
	AttestationJSON string `json:"attestation_json"`
}

// FinishRegistrationResponse contains the result of WebAuthn registration.
type FinishRegistrationResponse struct {
	Success      bool   `json:"success"`
	CredentialID string `json:"credential_id"`
	Token        string `json:"token,omitempty"`
	Message      string `json:"message,omitempty"`
}

// The authentication (login) ceremony is lossless and symmetric to
// registration: BeginAuthentication returns the full JSON-marshaled WebAuthn
// options (CredentialAssertion) and an opaque session ID, and
// FinishAuthentication carries the full WebAuthn PublicKeyCredential assertion
// JSON back to the server. This mirrors the browser ceremony served by
// pkg/webauthn/http exactly, just transported over the SDK.

// BeginAuthenticationRequest contains parameters to begin a WebAuthn authentication.
type BeginAuthenticationRequest struct {
	// Email is the canonical tenant-unique login key of the account whose
	// registered credentials are challenged. The service resolves the account
	// with GetUserByEmail; a username is a different identifier and is not
	// accepted.
	Email string `json:"email"`
}

// BeginAuthenticationResponse carries the session ID and the JSON-marshaled
// WebAuthn authentication options produced by the relying party.
type BeginAuthenticationResponse struct {
	// SessionID is the opaque server-side session identifier that must be
	// echoed back to FinishAuthentication to correlate the ceremony.
	SessionID string `json:"session_id"`

	// OptionsJSON is the JSON-marshaled *protocol.CredentialAssertion
	// (PublicKeyCredentialRequestOptions) that the client hands to the
	// authenticator via navigator.credentials.get().
	OptionsJSON string `json:"options_json"`
}

// FinishAuthenticationRequest carries the authenticator assertion back to the
// server to complete the authentication ceremony.
type FinishAuthenticationRequest struct {
	// SessionID is the value returned by BeginAuthentication.
	SessionID string `json:"session_id"`

	// Email is the canonical tenant-unique login key of the account whose
	// credentials are being asserted; the service resolves it with
	// GetUserByEmail.
	Email string `json:"email"`

	// AssertionJSON is the WebAuthn PublicKeyCredential JSON produced by the
	// authenticator (the response from navigator.credentials.get()). It is the
	// exact body that protocol.ParseCredentialRequestResponseBody expects.
	AssertionJSON string `json:"assertion_json"`
}

// FinishAuthenticationResponse contains the result of WebAuthn authentication.
type FinishAuthenticationResponse struct {
	Success  bool   `json:"success"`
	Token    string `json:"token,omitempty"`
	Username string `json:"username,omitempty"`
	Message  string `json:"message,omitempty"`
}

// Invitation redemption (go-xkms#1294 part B): how an account CreateUser
// provisioned with zero credentials enrolls its first one. Every verb below
// is public/unauthenticated on every transport — there is no credential yet
// to authenticate a request with — and every unusable token (absent,
// expired, already redeemed, malformed) answers with the same opaque
// refusal so an unauthenticated caller cannot enumerate accounts.

// GetInviteRequest resolves a still-usable invitation's metadata without
// consuming it.
type GetInviteRequest struct {
	TenantID string `json:"tenant_id"`
	Token    string `json:"token"`
}

// GetInviteResponse is the invitation metadata an unauthenticated
// activation page reads to render itself.
type GetInviteResponse struct {
	Email       string    `json:"email,omitempty"`
	DisplayName string    `json:"display_name,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
	// Methods lists the credential kinds this build can activate an invite
	// with ("webauthn", "piv").
	Methods []string `json:"methods"`
}

// BeginInviteRegistrationRequest opens the invite-authorized WebAuthn
// registration ceremony for the token's account.
type BeginInviteRegistrationRequest struct {
	TenantID string `json:"tenant_id"`
	Token    string `json:"token"`
}

// BeginInviteRegistrationResponse carries the begun ceremony: the full
// CredentialCreation options, JSON-marshaled so callers do not need the
// go-webauthn types, and the opaque session ID
// FinishInviteRegistrationRequest echoes back.
type BeginInviteRegistrationResponse struct {
	SessionID   string `json:"session_id"`
	OptionsJSON string `json:"options_json"`
}

// FinishInviteRegistrationRequest completes the invite-authorized WebAuthn
// registration ceremony: it binds the credential to the still-pending
// account, activates the account, and redeems the invitation, in that safe
// order.
type FinishInviteRegistrationRequest struct {
	TenantID        string `json:"tenant_id"`
	Token           string `json:"token"`
	SessionID       string `json:"session_id"`
	AttestationJSON string `json:"attestation_json"`
}

// FinishInviteRegistrationResponse reports which account the redemption
// activated.
type FinishInviteRegistrationResponse struct {
	UserID uint64 `json:"user_id,string"`
}

// ActivateInvitePIVRequest completes PIV invite activation: it verifies the
// presented certificate's chain against the CA's trust roots, binds its
// SPKI thumbprint to the still-pending account, activates the account, and
// redeems the invitation — the same safe order
// FinishInviteRegistrationRequest uses.
type ActivateInvitePIVRequest struct {
	TenantID string `json:"tenant_id"`
	Token    string `json:"token"`
	CertPEM  string `json:"cert_pem"`
}

// ActivateInvitePIVResponse reports which account the redemption activated.
type ActivateInvitePIVResponse struct {
	UserID uint64 `json:"user_id,string"`
}

// DeriveKeyECDHRequest contains parameters for ECDH key agreement and derivation.
// This combines ECDH shared secret computation with a KDF to produce a derived key.
type DeriveKeyECDHRequest struct {
	// KeyID identifies the local private key to use for ECDH
	// This key must be an EC key (P-256, P-384, P-521, or X25519)
	KeyID string `json:"key_id"`

	// Backend specifies which backend contains the private key
	Backend string `json:"backend"`

	// PeerPublicKey is the peer's public key in DER or uncompressed point format
	// The public key must use the same curve as the private key
	PeerPublicKey []byte `json:"peer_public_key"`

	// KDFAlgorithm specifies the KDF to apply to the raw ECDH shared secret
	// Supported values: "HKDF", "SP800-108-COUNTER", "SP800-108-FEEDBACK",
	// "SP800-56A", "X963". If empty, defaults to "HKDF"
	KDFAlgorithm string `json:"kdf_algorithm,omitempty"`

	// KDFHash specifies the hash algorithm for the KDF
	// Supported values: "SHA-256", "SHA-384", "SHA-512". Defaults to "SHA-256"
	KDFHash string `json:"kdf_hash,omitempty"`

	// KDFSalt is an optional salt value for the KDF
	// For HKDF, this is used in the extract phase
	KDFSalt []byte `json:"kdf_salt,omitempty"`

	// KDFInfo is optional context/application-specific information
	// For HKDF, this is used in the expand phase
	// For the SP 800-108 modes, this is the Context
	KDFInfo []byte `json:"kdf_info,omitempty"`

	// KDFLabel is the SP 800-108 Label, the purpose string bound into the
	// fixed input data as Label || 0x00 || Context || [L]_2 (SP 800-108r1 §4).
	//
	// It is what gives a derivation domain separation: two protocols deriving
	// from the same ECDH shared secret with the same Context but different
	// Labels get different keys, and without it they get the same key. An
	// empty label is valid SP 800-108 and remains the default, so a caller
	// that omits it derives exactly what it did before this field existed.
	//
	// SP 800-108 only. The concatenation KDFs (X9.63, SP 800-56A) and HKDF
	// have no label input and reject a non-empty value rather than dropping it.
	KDFLabel []byte `json:"kdf_label,omitempty"`

	// KeyLength specifies the desired output key length in bytes
	// Common values: 16 (AES-128), 32 (AES-256). Defaults to 32
	KeyLength int `json:"key_length,omitempty"`

	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`

	// KeyVersion optionally names the version of the local key to agree
	// with; it must be enabled. Zero uses the current version.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// DeriveKeyECDHResponse contains the derived key from ECDH key agreement.
type DeriveKeyECDHResponse struct {
	// DerivedKey is the key material derived from ECDH + KDF
	DerivedKey []byte `json:"derived_key"`

	// KeyVersion is the version of the local key the agreement used.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// WrapKeyByIDRequest contains parameters for wrapping a key using another key.
// Both keys are identified by their IDs (server-side key wrap).
type WrapKeyByIDRequest struct {
	// WrappingKeyID is the ID of the key used for wrapping (Key Encryption Key)
	WrappingKeyID string `json:"wrapping_key_id"`

	// WrappingKeyBackend is the backend containing the wrapping key
	WrappingKeyBackend string `json:"wrapping_key_backend"`

	// TargetKeyID is the ID of the key to be wrapped (must be extractable).
	// Exactly one of TargetKeyID and TargetKeyMaterial must be set.
	TargetKeyID string `json:"target_key_id"`

	// TargetKeyBackend is the backend containing the target key. It is
	// required with TargetKeyID and ignored with TargetKeyMaterial.
	TargetKeyBackend string `json:"target_key_backend"`

	// TargetKeyMaterial is the plaintext of a key the caller already holds,
	// for a wrap whose target is not resident in any backend.
	//
	// PKCS#11 C_WrapKey must work on a key imported with C_CreateObject and
	// CKA_VALUE, which exists only in the caller's own object store and has no
	// backend key ID to name here. Sending the material is what lets such a
	// wrap run through the one wrap implementation (servicer_wrapkey.go)
	// instead of a second one: a caller that encrypts the material itself
	// produces a blob framed differently from the one UnwrapKeyByID parses,
	// which is unrecoverable rather than merely non-interoperable.
	//
	// This grants no capability the API did not already have: EncryptRequest
	// carries caller plaintext to the same backend under the same key, and is
	// exactly what such a caller used before.
	TargetKeyMaterial []byte `json:"target_key_material,omitempty"`

	// Algorithm specifies the wrapping algorithm
	// Supported: "RSAES_OAEP_SHA_256", "AES_KEY_WRAP", etc.
	Algorithm string `json:"algorithm"`

	// IV is the initialization vector or nonce the mechanism requires:
	// CK_GCM_PARAMS.pIv for AES-GCM, the 16-byte IV for AES-CBC and
	// AES-CBC-PAD. Empty asks the service to generate one; either way it is
	// carried in the wrapped blob, so UnwrapKeyByID needs no IV to reverse it.
	IV []byte `json:"iv,omitempty"`

	// AAD is CK_GCM_PARAMS.pAAD, the additional authenticated data bound to an
	// AES-GCM wrap. It is authenticated, not encrypted, so it is not carried
	// in the blob: UnwrapKeyByIDRequest.AAD must repeat it.
	AAD []byte `json:"aad,omitempty"`

	// TagBits is CK_GCM_PARAMS.ulTagBits, the AES-GCM authentication tag
	// length in bits (96, 104, 112, 120 or 128). Zero selects the full-length
	// tag.
	TagBits int `json:"tag_bits,omitempty"`

	// OAEPLabel is CK_RSA_PKCS_OAEP_PARAMS.pSourceData, the RSA-OAEP label
	// (the "encoding parameter" of RFC 8017 §7.1). It is bound into the
	// ciphertext, so UnwrapKeyByIDRequest.OAEPLabel must repeat it exactly or
	// the unwrap fails. Empty means no label.
	OAEPLabel []byte `json:"oaep_label,omitempty"`

	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// WrapKeyByIDResponse contains the wrapped key material from server-side wrap.
type WrapKeyByIDResponse struct {
	// WrappedKey is the encrypted key material
	WrappedKey []byte `json:"wrapped_key"`

	// Algorithm is the algorithm used for wrapping
	Algorithm string `json:"algorithm"`

	// WrappingKeyVersion is the version of the wrapping key that wrapped the
	// key: always the current one. Pass it back on UnwrapKeyByID.
	WrappingKeyVersion uint32 `json:"wrapping_key_version,omitempty"`
}

// UnwrapKeyByIDRequest contains parameters for unwrapping key material
// and importing it as a new key (server-side unwrap).
type UnwrapKeyByIDRequest struct {
	// WrappedKey is the wrapped key material to unwrap
	WrappedKey []byte `json:"wrapped_key"`

	// UnwrappingKeyID is the ID of the key used for unwrapping
	UnwrappingKeyID string `json:"unwrapping_key_id"`

	// UnwrappingKeyBackend is the backend containing the unwrapping key
	UnwrappingKeyBackend string `json:"unwrapping_key_backend"`

	// Algorithm is the unwrapping algorithm used
	Algorithm string `json:"algorithm"`

	// IV is the initialization vector or nonce the mechanism requires. It is
	// normally left empty: every mechanism that needs one carries it inside
	// WrappedKey, in the framing WrapKeyByID produced. It exists so a caller
	// holding a blob produced elsewhere, without that framing, can supply it.
	IV []byte `json:"iv,omitempty"`

	// AAD is CK_GCM_PARAMS.pAAD. Unlike the IV it is never carried in the
	// blob, because it is authenticated rather than encrypted, so an AES-GCM
	// wrap made with AAD can only be reversed by repeating it here.
	AAD []byte `json:"aad,omitempty"`

	// TagBits is CK_GCM_PARAMS.ulTagBits. It must equal the value the wrap
	// used: NIST SP 800-38D §5.2.2 verifies a t-bit tag against a tag
	// recomputed at t bits, so a mismatch reads as a forgery.
	TagBits int `json:"tag_bits,omitempty"`

	// OAEPLabel is CK_RSA_PKCS_OAEP_PARAMS.pSourceData. It must equal the
	// label the wrap used, or RSA-OAEP decoding fails.
	OAEPLabel []byte `json:"oaep_label,omitempty"`

	// TargetKeyID is the ID for the new key
	TargetKeyID string `json:"target_key_id"`

	// TargetKeyBackend is the backend to store the new key
	TargetKeyBackend string `json:"target_key_backend"`

	// TargetKeyType is the key type: "symmetric", "rsa", "ecdsa", "ed25519"
	TargetKeyType string `json:"target_key_type"`

	// TargetKeySize is the key size in bits (e.g., 128, 192, 256 for AES)
	TargetKeySize int `json:"target_key_size,omitempty"`

	// TargetCurve is the curve for ECDSA keys (e.g., "P-256", "P-384")
	TargetCurve string `json:"target_curve,omitempty"`

	// TargetPartition is the partition for the new key
	TargetPartition string `json:"target_partition,omitempty"`

	// TargetExportable indicates whether the new key can be exported
	TargetExportable bool `json:"target_exportable,omitempty"`

	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`

	// UnwrappingKeyVersion optionally names the unwrapping key's version; it
	// must be enabled. Zero tries every enabled version, newest first, for
	// AES-KW, AES-KWP, AES-GCM and RSA-OAEP, and requires exactly one enabled
	// version for AES-CBC and RSA PKCS#1 v1.5.
	UnwrappingKeyVersion uint32 `json:"unwrapping_key_version,omitempty"`
}

// UnwrapKeyByIDResponse contains the result of server-side key unwrap.
type UnwrapKeyByIDResponse struct {
	// KeyID is the ID of the newly created key
	KeyID string `json:"key_id"`

	// Backend is the backend where the key was stored
	Backend string `json:"backend"`

	// Success indicates whether the operation succeeded
	Success bool `json:"success"`

	// Message is a status message
	Message string `json:"message,omitempty"`
}

// ExportKeyMaterialRequest requests export of raw symmetric key bytes.
//
// SECURITY WARNING: This exports plaintext key material without cryptographic
// protection. Only use for extractable symmetric keys.
type ExportKeyMaterialRequest struct {
	// KeyID is the key identifier
	KeyID string `json:"key_id"`

	// Backend is the backend containing the key
	Backend string `json:"backend"`

	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// ExportKeyMaterialResponse contains the raw key material.
//
// SECURITY WARNING: The KeyMaterial field contains plaintext secret key bytes.
// Handle with extreme care.
type ExportKeyMaterialResponse struct {
	// KeyMaterial is the raw key bytes (plaintext symmetric key material).
	// It is caller-owned: the receiver may seal and wipe it, so an
	// implementation must never return a slice it still holds.
	KeyMaterial []byte `json:"key_material"`

	// KeyType is the type of the key (e.g., "aes256-gcm", "chacha20-poly1305")
	KeyType string `json:"key_type"`

	// KeySize is the size of the key in bits (e.g., 128, 192, 256)
	KeySize int `json:"key_size"`
}

// DeriveKeyRequest contains parameters for key derivation operations.
// Supports HKDF, ECDH, DH, SP800-108, and other key derivation mechanisms.
type DeriveKeyRequest struct {
	Backend string `json:"backend"`          // Backend identifier
	KeyID   string `json:"key_id,omitempty"` // Source key ID (for key-based derivation like ECDH)

	// Algorithm specifies the key derivation algorithm
	// Supported: "HKDF", "ECDH", "DH", "SP800-108-COUNTER", "SP800-108-FEEDBACK", "PBKDF2"
	Algorithm string `json:"algorithm"`

	// InputKeyMaterial is the input key material for derivation (for HKDF without a key)
	InputKeyMaterial []byte `json:"input_key_material,omitempty"`

	// Salt is the salt value for the KDF
	Salt []byte `json:"salt,omitempty"`

	// Info is the context/application-specific info (for HKDF)
	Info []byte `json:"info,omitempty"`

	// PeerPublicKey is the peer's public key (for ECDH/DH key agreement)
	PeerPublicKey []byte `json:"peer_public_key,omitempty"`

	// KeyLength is the desired output key length in bytes
	KeyLength int `json:"key_length"`

	// Hash specifies the hash algorithm (e.g., "SHA-256", "SHA-384", "SHA-512")
	Hash string `json:"hash,omitempty"`

	// Iterations is the iteration count (for PBKDF2)
	Iterations int `json:"iterations,omitempty"`

	// PRF specifies the pseudo-random function for SP800-108
	PRF string `json:"prf,omitempty"`

	// Label is the label for SP800-108
	Label []byte `json:"label,omitempty"`

	// Context is the context for SP800-108
	Context []byte `json:"context,omitempty"`

	// Counter is the counter value for SP800-108 counter mode
	Counter uint32 `json:"counter,omitempty"`

	// UseCofactor enables cofactor multiplication for ECDH
	UseCofactor bool `json:"use_cofactor,omitempty"`

	// StoreResult specifies whether to store the derived key in the backend
	StoreResult bool `json:"store_result,omitempty"`

	// DerivedKeyID is the key ID for the stored derived key
	DerivedKeyID string `json:"derived_key_id,omitempty"`

	// DerivedKeyType is the type of the derived key (e.g., "AES", "HMAC")
	DerivedKeyType string `json:"derived_key_type,omitempty"`

	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
	// KeyVersion optionally names the version of the stored base key to
	// derive from; it must be enabled. Zero derives from the current
	// version. A derivation is only reproducible under the same version.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// DeriveKeyResponse contains the result of key derivation.
type DeriveKeyResponse struct {
	// DerivedKey is the derived key material (if StoreResult is false)
	DerivedKey []byte `json:"derived_key,omitempty"`

	// KeyID is the key ID of the stored derived key (if StoreResult is true)
	KeyID string `json:"key_id,omitempty"`

	// Algorithm is the algorithm used for derivation
	Algorithm string `json:"algorithm"`

	// KeyLength is the actual output key length in bytes
	KeyLength int `json:"key_length"`

	// KeyVersion is the version of the stored base key the key was derived
	// from; zero when the derivation used caller-supplied key material.
	KeyVersion uint32 `json:"key_version,omitempty"`
}

// CA Operations

// GetCABundleRequest contains parameters for retrieving a CA certificate bundle.
type GetCABundleRequest struct {
	StoreType string `json:"store_type,omitempty"` // Filter: "software", "tpm2", "pkcs11"
	Algorithm string `json:"algorithm,omitempty"`  // Filter: "RSA", "ECDSA", "Ed25519"
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// GetCABundleResponse contains the CA certificate bundle.
type GetCABundleResponse struct {
	BundlePEM    []byte   `json:"bundle_pem"`   // PEM-encoded certificate chain
	Certificates [][]byte `json:"certificates"` // Individual DER-encoded certificates
	ContentType  string   `json:"content_type"` // MIME type
}

// GetCACertificateRequest contains parameters for retrieving the CA certificate.
type GetCACertificateRequest struct {
	Identity string `json:"identity,omitempty"` // CA identity (CN), empty for default
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// GetCACertificateResponse contains the CA certificate.
type GetCACertificateResponse struct {
	CertificatePEM []byte `json:"certificate_pem"`
	Subject        string `json:"subject"`
	Issuer         string `json:"issuer"`
	SerialNumber   string `json:"serial_number"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	IsCA           bool   `json:"is_ca"`
}

// SignCSRRequest contains parameters for signing a certificate signing request.
type SignCSRRequest struct {
	CSRPEM       []byte `json:"csr_pem"`                 // PEM-encoded PKCS#10 CSR
	Profile      string `json:"profile,omitempty"`       // Certificate profile: server, client, idevid, etc.
	ValidityDays int    `json:"validity_days,omitempty"` // Override default validity
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
	// SPIFFEKind optionally selects the workload kind of the certificate's
	// tenant SPIFFE URI SAN, spiffe://<tenant>/<kind>/<CSR CommonName>:
	// "user" (spiffe.KindUser) or "svc" (spiffe.KindService). Empty keeps
	// the default, a user identity when the request names a tenant. A kind
	// requires TenantID and a configured trust domain, and "svc" requires
	// the certs:issue_service permission (go-xkms#1659).
	SPIFFEKind string `json:"spiffe_kind,omitempty"`
	// Attestation fields (optional). When present, the server verifies the
	// attestation proof before signing. This proves the CSR's private key
	// is stored in hardware (YubiKey PIV, TPM2, etc.).
	AttestationFormat string   `json:"attestation_format,omitempty"` // "tpm2", "yubikey-piv"
	AttestationChain  [][]byte `json:"attestation_chain,omitempty"`  // DER-encoded attestation cert chain
	AttestationData   []byte   `json:"attestation_data,omitempty"`   // Format-specific attestation evidence
	AttestationSig    []byte   `json:"attestation_sig,omitempty"`    // Signature over attestation data
	AttestationNonce  []byte   `json:"attestation_nonce,omitempty"`  // Freshness nonce
}

// SignCSRResponse contains the signed certificate.
type SignCSRResponse struct {
	CertificatePEM []byte `json:"certificate_pem"`
	ChainPEM       []byte `json:"chain_pem"`
	SerialNumber   string `json:"serial_number"`
}

// IssueCertificateRequest contains parameters for issuing a new certificate.
type IssueCertificateRequest struct {
	Profile      string   `json:"profile"` // server, client, idevid, etc.
	CommonName   string   `json:"common_name"`
	Organization string   `json:"organization,omitempty"`
	SANs         []string `json:"sans,omitempty"` // DNS:..., IP:..., Email:...
	ValidityDays int      `json:"validity_days,omitempty"`
	Algorithm    string   `json:"algorithm,omitempty"` // ecdsa-p256, rsa2048, ed25519
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// IssueCertificateResponse contains the issued certificate and optional private key.
type IssueCertificateResponse struct {
	CertificatePEM []byte `json:"certificate_pem"`
	ChainPEM       []byte `json:"chain_pem"`
	PrivateKeyPEM  []byte `json:"private_key_pem,omitempty"` // Only if key was generated
	SerialNumber   string `json:"serial_number"`
}

// RevokeCertificateRequest contains parameters for revoking a certificate.
type RevokeCertificateRequest struct {
	SerialNumber string `json:"serial_number"`
	Reason       int    `json:"reason"` // RFC 5280 reason code
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// RevokeCertificateResponse contains the result of revocation.
type RevokeCertificateResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// GenerateCRLRequest contains parameters for generating a CRL.
type GenerateCRLRequest struct {
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// GenerateCRLResponse contains the generated CRL.
type GenerateCRLResponse struct {
	CRLPEM []byte `json:"crl_pem"`
}

// IsRevokedRequest checks if a certificate is revoked.
type IsRevokedRequest struct {
	SerialNumber string `json:"serial_number"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// IsRevokedResponse contains the revocation status.
type IsRevokedResponse struct {
	Revoked bool   `json:"revoked"`
	Reason  int    `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// TCG CA Operations

// IssueEKCertificateRequest contains parameters for issuing an EK certificate.
type IssueEKCertificateRequest struct {
	CommonName   string `json:"common_name"`
	Organization string `json:"organization,omitempty"`
	EKPublicKey  []byte `json:"ek_public_key"` // DER-encoded public key
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// IssueEKCertificateResponse contains the issued EK certificate.
type IssueEKCertificateResponse struct {
	CertificateDER []byte `json:"certificate_der"`
	CertificatePEM []byte `json:"certificate_pem"`
	SerialNumber   string `json:"serial_number"`
}

// IssueAKCertificateRequest contains parameters for issuing an AK certificate.
type IssueAKCertificateRequest struct {
	CommonName   string `json:"common_name"`
	Organization string `json:"organization,omitempty"`
	PublicKey    []byte `json:"public_key"` // DER-encoded public key
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// IssueAKCertificateResponse contains the issued AK certificate.
type IssueAKCertificateResponse struct {
	CertificateDER []byte `json:"certificate_der"`
	CertificatePEM []byte `json:"certificate_pem"`
	SerialNumber   string `json:"serial_number"`
}

// SignTCGCSRRequest contains parameters for signing a TCG-CSR-IDEVID.
type SignTCGCSRRequest struct {
	CommonName   string `json:"common_name"`
	Organization string `json:"organization,omitempty"`
	TCGCSR       []byte `json:"tcg_csr"` // Packed TCG_CSR_IDEVID binary
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// SignTCGCSRResponse contains the signed IAK and IDevID certificates.
type SignTCGCSRResponse struct {
	IAKCertDER    []byte `json:"iak_cert_der"`
	IDevIDCertDER []byte `json:"idevid_cert_der"`
}

// EnrollDeviceRequest contains parameters for TCG device enrollment.
type EnrollDeviceRequest struct {
	CommonName   string `json:"common_name"`
	Organization string `json:"organization,omitempty"`
	PackedCSR    []byte `json:"packed_csr"` // Packed TCG_CSR_IDEVID binary
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// EnrollDeviceResponse contains the enrollment result with certificates and challenge.
type EnrollDeviceResponse struct {
	IAKCertDER      []byte `json:"iak_cert_der"`
	IDevIDCertDER   []byte `json:"idevid_cert_der"`
	CredentialBlob  []byte `json:"credential_blob"`
	EncryptedSecret []byte `json:"encrypted_secret"`
	PlainSecret     []byte `json:"plain_secret"`
}

// IssueLAKCertificateRequest contains the TPM2_Certify evidence and TPM
// device attributes for issuing a Local Attestation Key certificate in the
// WebAuthn Level 2 §8.3.1 profile (go-xkms#715). The LAK's certificate has
// no Subject (§8.3.1 requirement 2), so unlike every other TCG issuance
// request here this carries no CommonName/Organization.
type IssueLAKCertificateRequest struct {
	// TPMManufacturer, TPMModel and TPMFirmwareVersion identify the TPM chip
	// itself; they populate the certificate's critical subjectAltName
	// directoryName (§8.3.1 requirement 3).
	TPMManufacturer    string `json:"tpm_manufacturer"`
	TPMModel           string `json:"tpm_model"`
	TPMFirmwareVersion string `json:"tpm_firmware_version"`
	// IAKCertificateDER is the device's own IAK certificate (DER), issued by
	// a prior SignTCGCSR/EnrollDevice call. The evidence below is verified
	// against it.
	IAKCertificateDER []byte `json:"iak_certificate_der"`
	// CertifyInfo and Signature are the raw TPM2_Certify evidence: the
	// TPMS_ATTEST the IAK certified the LAK's public area with, and the
	// IAK's ordinary X.509-form signature over it (ASN.1 DER for ECDSA, the
	// raw big-endian value for RSA -- not a marshalled TPMT_SIGNATURE).
	CertifyInfo []byte `json:"certify_info"`
	Signature   []byte `json:"signature"`
	// SignatureAlgorithm is the IAK's signature algorithm, an
	// x509.SignatureAlgorithm value.
	SignatureAlgorithm int `json:"signature_algorithm"`
	// LAKPublicArea is the LAK's marshalled TPMT_PUBLIC: the subject
	// TPM2_Certify names.
	LAKPublicArea []byte `json:"lak_public_area"`
	// Nonce is the qualifying data the evidence must echo.
	Nonce []byte `json:"nonce"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// IssueLAKCertificateResponse contains the issued LAK certificate.
type IssueLAKCertificateResponse struct {
	CertificateDER []byte `json:"certificate_der"`
	CertificatePEM []byte `json:"certificate_pem"`
	SerialNumber   string `json:"serial_number"`
}

// PIV Operations

// ListPIVSlotsRequest contains parameters for listing PIV slots.
type ListPIVSlotsRequest struct {
	Backend string `json:"backend"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
	PageRequest
}

// PIVSlotStatus contains the status of a single PIV slot.
type PIVSlotStatus struct {
	Slot        string `json:"slot"`
	Name        string `json:"name"`
	Description string `json:"description"`
	HasCert     bool   `json:"has_cert"`
	HasKey      bool   `json:"has_key"`
	Subject     string `json:"subject,omitempty"`
	Issuer      string `json:"issuer,omitempty"`
	Algorithm   string `json:"algorithm,omitempty"`
	KeySize     int    `json:"key_size,omitempty"`
	NotAfter    string `json:"not_after,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Backend     string `json:"backend,omitempty"`
}

// ListPIVSlotsResponse contains the list of PIV slots.
type ListPIVSlotsResponse struct {
	Slots []PIVSlotStatus `json:"slots"`
	PageResponse
}

// GetPIVCertificateRequest contains parameters for retrieving a PIV certificate.
type GetPIVCertificateRequest struct {
	Backend string `json:"backend"`
	Slot    string `json:"slot"`
	Format  string `json:"format"` // "pem" or "der"
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// GetPIVCertificateResponse contains the PIV certificate data.
type GetPIVCertificateResponse struct {
	Slot        string `json:"slot"`
	Certificate []byte `json:"certificate"`
	Format      string `json:"format"`
}

// StorePIVCertificateRequest contains parameters for storing a PIV certificate.
type StorePIVCertificateRequest struct {
	Backend     string `json:"backend"`
	Slot        string `json:"slot"`
	Certificate []byte `json:"certificate"`
	Format      string `json:"format"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// DeletePIVCertificateRequest contains parameters for deleting a PIV certificate.
type DeletePIVCertificateRequest struct {
	Backend string `json:"backend"`
	Slot    string `json:"slot"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// GeneratePIVKeyRequest contains parameters for generating a PIV key.
type GeneratePIVKeyRequest struct {
	Backend   string `json:"backend"`
	Slot      string `json:"slot"`
	Algorithm string `json:"algorithm"` // "rsa2048", "rsa4096", "ecdsap256", "ecdsap384", "ed25519"
	Subject   string `json:"subject"`
	// Organization is the X.509 Organization (O) field for the certificate subject.
	Organization string `json:"organization,omitempty"`
	// Country is the X.509 Country (C) field for the certificate subject.
	Country string `json:"country,omitempty"`
	// OutputFormat controls what is produced: "self-signed" (default), "public-key",
	// "csr", or "ca-signed". Empty string is treated as "self-signed".
	OutputFormat string `json:"output_format,omitempty"`
	// ValidityDays overrides the default certificate validity period. Zero uses
	// the profile default (3 years for CA-signed, 10 years for self-signed).
	ValidityDays int `json:"validity_days,omitempty"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// GeneratePIVKeyResponse contains the result of PIV key generation.
type GeneratePIVKeyResponse struct {
	Slot        string `json:"slot"`
	Certificate []byte `json:"certificate"`         // Cert PEM (self-signed or CA-signed)
	PublicKey   []byte `json:"public_key"`          // Public key PEM
	CSR         []byte `json:"csr,omitempty"`       // CSR PEM (populated when OutputFormat is "csr")
	ChainPEM    []byte `json:"chain_pem,omitempty"` // CA chain PEM (populated when OutputFormat is "ca-signed")
}

// GeneratePIVCSRRequest contains parameters for generating a PIV CSR.
// Subject holds the Common Name (CN) for backwards compatibility. Additional
// DN fields (Organization, OrganizationalUnit, Country, State, Locality) are
// optional and populated when the caller supplies them; all empty values
// simply produce an RFC 5280 DN without that attribute.
type GeneratePIVCSRRequest struct {
	Backend            string `json:"backend"`
	Slot               string `json:"slot"`
	Subject            string `json:"subject"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
	Country            string `json:"country,omitempty"`
	State              string `json:"state,omitempty"`
	Locality           string `json:"locality,omitempty"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// GeneratePIVCSRResponse contains the generated CSR.
type GeneratePIVCSRResponse struct {
	Slot string `json:"slot"`
	CSR  []byte `json:"csr"` // PEM-encoded
}

// Trust Bootstrap Listener

// BootstrapListenerKeysResponse reports the running trust-bootstrap
// listener's public static keys (go-xkms#632), for an administrator to
// distribute to first-contact clients. Only public material is ever
// returned; the private scalars never leave
// pkg/server/bootstrap_key_custody.go's protected memory.
//
// Both fields are hex-encoded in exactly the form
// pkg/trust/bootstrap.NoiseConfig accepts — a first-contact client pastes
// NoisePublicKey into NoiseConfig.ServerStaticKey (or `--noise-key`) and
// P256PublicKey into NoiseConfig.ServerP256StaticKey (or `--p256-key`); both
// are validated there the same way (decodeSuiteKey: hex-decode, then a
// suite-specific length check). There is no SPKI pin here: nothing in the
// stack pins the Noise/P-256 responder key by hashing it — the raw public
// key IS the pin for this transport, exactly as go-truststrap's
// suite-negotiating client already consumes it.
//
// A field is empty when that suite is not offered — a FIPS build never
// publishes NoisePublicKey (Noise_NK is not FIPS-approved), and a build with
// no P-256 key configured leaves P256PublicKey empty. At least one field is
// populated whenever the response is returned at all: an unenabled listener
// is reported as ErrBootstrapListenerNotEnabled, never as a response with
// both fields empty.
type BootstrapListenerKeysResponse struct {
	// NoisePublicKey is the hex-encoded Noise_NK (X25519) static public key
	// — the value for NoiseConfig.ServerStaticKey / `--noise-key`.
	NoisePublicKey string `json:"noise_public_key,omitempty"`
	// P256PublicKey is the hex-encoded uncompressed P-256 static public key
	// of the FIPS-approved TSBOOT1_P256_AESGCM_SHA256 suite — the value for
	// NoiseConfig.ServerP256StaticKey / `--p256-key`.
	P256PublicKey string `json:"p256_public_key,omitempty"`
}

// PIN Operations

// SetSOPINRequest contains parameters for setting the Security Officer PIN.
type SetSOPINRequest struct {
	CurrentSOPIN string `json:"current_so_pin"` // Empty string if not yet set
	NewSOPIN     string `json:"new_so_pin"`
}

// SetUserPINRequest contains parameters for setting the user PIN.
type SetUserPINRequest struct {
	SOPIN      string `json:"so_pin"`
	NewUserPIN string `json:"new_user_pin"`
}

// ChangeSOPINRequest contains parameters for changing the SO PIN.
type ChangeSOPINRequest struct {
	CurrentSOPIN string `json:"current_so_pin"`
	NewSOPIN     string `json:"new_so_pin"`
}

// ChangeUserPINRequest contains parameters for changing the user PIN.
type ChangeUserPINRequest struct {
	CurrentUserPIN string `json:"current_user_pin"`
	NewUserPIN     string `json:"new_user_pin"`
}

// VerifySOPINRequest contains parameters for verifying the SO PIN.
type VerifySOPINRequest struct {
	SOPIN string `json:"so_pin"`
}

// VerifyUserPINRequest contains parameters for verifying the user PIN.
type VerifyUserPINRequest struct {
	UserPIN string `json:"user_pin"`
}

// LockoutStatusResponse contains the current PIN lockout status.
type LockoutStatusResponse struct {
	FailedAttempts  int    `json:"failed_attempts"`
	MaxAttempts     int    `json:"max_attempts"`
	IsLocked        bool   `json:"is_locked"`
	LockoutUntil    string `json:"lockout_until,omitempty"`
	RecoverySeconds int    `json:"recovery_seconds"`
}

// ResetLockoutRequest contains parameters for resetting the PIN lockout.
type ResetLockoutRequest struct {
	SOPIN string `json:"so_pin"`
}

// Password Store Operations

// PasswordAddRequest contains parameters for adding a static password.
type PasswordAddRequest struct {
	Name       string `json:"name"`
	Title      string `json:"title,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password"`
	URL        string `json:"url,omitempty"`
	Notes      string `json:"notes,omitempty"`
	FolderPath string `json:"folder_path,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	TenantID   string `json:"tenant_id,omitempty"`
	Shared     bool   `json:"shared,omitempty"`
}

// PasswordAddResponse contains the result of adding a password.
type PasswordAddResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

// PasswordGetRequest contains parameters for retrieving a password.
type PasswordGetRequest struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id,omitempty"`
}

// PasswordGetResponse contains a password entry.
type PasswordGetResponse struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Title      string `json:"title,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	URL        string `json:"url,omitempty"`
	Notes      string `json:"notes,omitempty"`
	FolderPath string `json:"folder_path,omitempty"`
	BackendID  string `json:"backend_id,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
	ReadOnly   bool   `json:"read_only,omitempty"`
	Encrypted  bool   `json:"encrypted"`
	OwnerID    string `json:"owner_id,omitempty"`
	Shared     bool   `json:"shared,omitempty"`
}

// PasswordListRequest contains parameters for listing passwords.
type PasswordListRequest struct {
	FolderPath string `json:"folder_path,omitempty"`
	TenantID   string `json:"tenant_id,omitempty"`
	Scope      string `json:"scope,omitempty"`
	PageRequest
}

// PasswordListResponse contains a list of password entries.
type PasswordListResponse struct {
	Passwords []PasswordGetResponse `json:"passwords"`
	PageResponse
}

// PasswordUpdateRequest contains parameters for updating a password.
type PasswordUpdateRequest struct {
	ID         string  `json:"id"`
	Name       *string `json:"name,omitempty"`
	Title      *string `json:"title,omitempty"`
	Username   *string `json:"username,omitempty"`
	Password   *string `json:"password,omitempty"`
	URL        *string `json:"url,omitempty"`
	Notes      *string `json:"notes,omitempty"`
	FolderPath *string `json:"folder_path,omitempty"`
	ExpiresAt  *string `json:"expires_at,omitempty"`
	TenantID   string  `json:"tenant_id,omitempty"`
}

// PasswordDeleteRequest contains parameters for deleting a password.
type PasswordDeleteRequest struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id,omitempty"`
}

// PasswordVaultCredential is a factor of the caller's personal vault: a
// passphrase, a passkey (a FIDO2 credential with the hmac-secret / WebAuthn
// PRF extension), or a key factor -- a PIV slot 9d key, a certificate's key
// or a TPM key, whose secret only the private key recovers (pkg/vaultkey).
type PasswordVaultCredential struct {
	// Factor is "passphrase", "passkey", "piv", "certificate" or "tpm".
	Factor string `json:"factor"`

	// Passphrase is the passphrase (Factor "passphrase").
	Passphrase string `json:"passphrase,omitempty"`

	// CredentialID identifies the passkey (Factor "passkey").
	CredentialID []byte `json:"credential_id,omitempty"`

	// PRFSalt is the 32-byte salt the authenticator evaluated hmac-secret
	// over. Required to enroll a passkey; an enrolled passkey's salt is
	// reported by PasswordVaultStatus.
	PRFSalt []byte `json:"prf_salt,omitempty"`

	// Secret is the 32-byte hmac-secret (PRF) output (Factor "passkey"),
	// or the 32-byte secret a key factor's private key recovered from its
	// challenge (unlocking with a key factor).
	Secret []byte `json:"secret,omitempty"`

	// Label names an enrolled factor.
	Label string `json:"label,omitempty"`

	// RPID is the WebAuthn relying party ID the passkey was created for;
	// required to enroll a passkey, and it must be the server's
	// (PasswordVaultStatusResponse.PasskeyRPID).
	RPID string `json:"rp_id,omitempty"`

	// PublicKey (PKIX DER) or Certificate (DER) enrolls a key factor; a
	// certificate factor needs Certificate.
	PublicKey   []byte `json:"public_key,omitempty"`
	Certificate []byte `json:"certificate,omitempty"`

	// KeyFingerprint selects the key factor a key-factor unlock opens.
	KeyFingerprint string `json:"key_fingerprint,omitempty"`

	// KeyRef records where the client keeps a key factor's private key.
	KeyRef PasswordVaultKeyRef `json:"key_ref,omitzero"`
}

// PasswordVaultKeyRef is where a key factor's private key lives on the
// client: the xkms backend, the key's ID there, and a TPM key's named TPM
// policy. A hint for finding the token; the fingerprint proves the key.
type PasswordVaultKeyRef struct {
	Backend   string `json:"backend,omitempty"`
	KeyID     string `json:"key_id,omitempty"`
	TPMPolicy string `json:"tpm_policy,omitempty"`
}

// PasswordStoreUnlockRequest opens the caller's personal password session
// with one of the caller's own vault factors.
type PasswordStoreUnlockRequest struct {
	PasswordVaultCredential
}

// PasswordVaultFactor describes one enrolled factor (no key material).
type PasswordVaultFactor struct {
	ID           string `json:"id"`
	Factor       string `json:"factor"`
	Label        string `json:"label,omitempty"`
	CreatedAt    string `json:"created_at"`
	CredentialID []byte `json:"credential_id,omitempty"`
	PRFSalt      []byte `json:"prf_salt,omitempty"`

	// RPID is the relying party ID a passkey was created for: every
	// client evaluates it for this ID.
	RPID string `json:"rp_id,omitempty"`

	// Key factors: what a client needs to recover the factor's secret with
	// its private key (pkg/vaultkey.Factor), where the key is kept, and a
	// certificate's subject for display.
	KeyFingerprint     string              `json:"key_fingerprint,omitempty"`
	KeyAlgorithm       string              `json:"key_algorithm,omitempty"`
	KeyChallenge       []byte              `json:"key_challenge,omitempty"`
	KeyCheck           []byte              `json:"key_check,omitempty"`
	KeyRef             PasswordVaultKeyRef `json:"key_ref,omitzero"`
	CertificateSubject string              `json:"certificate_subject,omitempty"`
}

// PasswordVaultStatusResponse describes the caller's personal vault.
type PasswordVaultStatusResponse struct {
	Initialized bool                  `json:"initialized"`
	Unlocked    bool                  `json:"unlocked"`
	Factors     []PasswordVaultFactor `json:"factors"`

	// PasskeyRPID is the WebAuthn relying party ID a new passkey must be
	// created for -- the domain the web console is served from. Empty when
	// the deployment offers no passkeys.
	PasskeyRPID string `json:"passkey_rp_id,omitempty"`
}

// PasswordVaultEnrollRequest enrolls a factor. The first enrollment
// initializes the vault; later ones need the caller's session open.
type PasswordVaultEnrollRequest struct {
	PasswordVaultCredential
}

// PasswordVaultEnrollResponse is the enrolled factor and, on the first
// enrollment or a recovery, the new recovery code, shown exactly once.
type PasswordVaultEnrollResponse struct {
	Factor       PasswordVaultFactor `json:"factor"`
	RecoveryCode string              `json:"recovery_code,omitempty"`
}

// PasswordVaultRotateRequest replaces factor FactorID with a new secret of
// the same type.
type PasswordVaultRotateRequest struct {
	FactorID string `json:"factor_id"`
	PasswordVaultCredential
}

// PasswordVaultRemoveFactorRequest removes factor FactorID.
type PasswordVaultRemoveFactorRequest struct {
	FactorID string `json:"factor_id"`
}

// PasswordVaultRecoverRequest uses the one-time recovery code to enroll a new
// factor.
type PasswordVaultRecoverRequest struct {
	RecoveryCode string `json:"recovery_code"`
	PasswordVaultCredential
}

// PasswordStoreStatusResponse contains the password store status.
type PasswordStoreStatusResponse struct {
	AccessMode    string `json:"access_mode"`
	IsLocked      bool   `json:"is_locked"`
	BarrierSealed bool   `json:"barrier_sealed"`
	AutoUnsealed  bool   `json:"auto_unsealed"`
	PasswordCount int    `json:"password_count"`
}

// PasswordStoreSetAccessModeRequest contains parameters for setting the access mode.
type PasswordStoreSetAccessModeRequest struct {
	Mode string `json:"mode"`
}

// PasswordGenerateRequest contains parameters for generating a password.
type PasswordGenerateRequest struct {
	Length  int  `json:"length"`
	Upper   bool `json:"upper"`
	Lower   bool `json:"lower"`
	Digits  bool `json:"digits"`
	Symbols bool `json:"symbols"`
	// Charset names a charset ("all", "alphanumeric") or lists the
	// characters to draw from. It is mutually exclusive with the class
	// flags above.
	Charset string `json:"charset,omitempty"`
}

// PasswordGenerateResponse contains a generated password.
type PasswordGenerateResponse struct {
	Password string `json:"password"`
}

// Platform Store Operations

// SealStorePutRequest contains parameters for storing a secret.
type SealStorePutRequest struct {
	Name   string `json:"name"`
	Secret []byte `json:"secret"`
}

// SealStoreGetRequest contains parameters for retrieving a secret.
type SealStoreGetRequest struct {
	Name string `json:"name"`
}

// SealStoreGetResponse contains a retrieved secret.
type SealStoreGetResponse struct {
	Name   string `json:"name"`
	Secret []byte `json:"secret"`
}

// SealStoreDeleteRequest contains parameters for deleting a secret.
type SealStoreDeleteRequest struct {
	Name string `json:"name"`
}

// SealStoreListResponse contains a list of stored secret names.
type SealStoreListResponse struct {
	Names []string `json:"names"`
	PageResponse
}

// SealStoreResealRequest contains parameters for resealing a secret.
type SealStoreResealRequest struct {
	Name string `json:"name"`
}

// SealStoreStatusResponse contains the platform store status.
type SealStoreStatusResponse struct {
	Available   bool     `json:"available"`
	SealerID    string   `json:"sealer_id,omitempty"`
	SecretCount int      `json:"secret_count"`
	SecretNames []string `json:"secret_names,omitempty"`
}

// TPM Policy Operations
//
// A TPM policy is a named, TPM-authorized policy that many TPM keys and
// sealed objects of one tenant share (pkg/tpmpolicy). Every request names its
// tenant in TenantID: every caller may leave it empty (its own tenant, the
// system scope for a system-tenant caller) or name its own tenant, never
// another. OwnerAuth is the physical TPM's
// owner-hierarchy authorization; it is never logged or echoed.

// TPM policy condition types: the kinds of condition a branch of a named
// TPM policy ANDs together.
const (
	// TPMPolicyConditionPCR requires the selected PCRs of a bank to hold the
	// values captured when the policy was created or last updated.
	TPMPolicyConditionPCR = "pcr"

	// TPMPolicyConditionAuthValue requires the object's password.
	TPMPolicyConditionAuthValue = "auth_value"

	// TPMPolicyConditionLocality requires the command to come from one of
	// the allowed TPM localities (0 through 4).
	TPMPolicyConditionLocality = "locality"
)

// TPMPolicyCondition is one condition of a TPM policy branch. Only the
// fields of its Type are set.
type TPMPolicyCondition struct {
	// Type is TPMPolicyConditionPCR, TPMPolicyConditionAuthValue or
	// TPMPolicyConditionLocality.
	Type string `json:"type"`

	// Bank is a pcr condition's PCR bank (sha1, sha256, sha384, sha512) and
	// PCRs its selected PCR indices.
	Bank string `json:"bank,omitempty"`
	PCRs []uint `json:"pcrs,omitempty"`

	// PCRValues are a pcr condition's hex-encoded values, keyed by PCR
	// index, captured when the policy was created or last updated, and
	// PCRDigest the hex-encoded PolicyPCR digest over them. They are
	// reported, never supplied: a create request carrying them is refused.
	PCRValues map[uint]string `json:"pcr_values,omitempty"`
	PCRDigest string          `json:"pcr_digest,omitempty"`

	// Localities are a locality condition's allowed localities, 0 through 4.
	Localities []uint `json:"localities,omitempty"`
}

// TPMPolicyBranch is one branch of a TPM policy: the AND of its conditions,
// at most one of each type.
type TPMPolicyBranch struct {
	// Name identifies the branch within its policy. A create request may
	// leave it empty; the branch is then named branch-N, N its position
	// counted from 1.
	Name string `json:"name,omitempty"`

	Conditions []TPMPolicyCondition `json:"conditions"`

	// Approved reports whether the branch holds an approval. It is reported
	// on a policy and has no meaning in a create request.
	Approved bool `json:"approved"`

	// Reference identifies the signed reference values the branch was last
	// updated from; nil when its values were captured from the live PCRs.
	// Like Approved, it has no meaning in a create request.
	Reference *TPMPolicyReference `json:"reference,omitempty"`
}

// TPMPolicy describes a named TPM policy: an OR of branches, tried in order
// when an object bound to it is used.
type TPMPolicy struct {
	// Name is the policy's name, unique within its tenant's scope.
	Name string `json:"name"`

	// TenantID is the tenant whose scope holds the policy; empty for the
	// system scope.
	TenantID string `json:"tenant_id,omitempty"`

	// Description is free text, settable at creation and at any time after.
	Description string `json:"description,omitempty"`

	// Branches are the policy's branches. Their structure never changes
	// after creation; an update only replaces their PCR values.
	Branches []TPMPolicyBranch `json:"branches"`

	// Index is the policy's NV index, which objects bound to it follow.
	Index uint32 `json:"index"`

	// Approved reports whether every branch holds an approval; it is false
	// after a revoke until the next update. Epoch is the revocation-counter
	// value the approvals were signed at, and AuthorityGeneration the policy
	// authority that signed them.
	Approved            bool   `json:"approved"`
	Epoch               uint64 `json:"epoch,omitempty"`
	AuthorityGeneration uint64 `json:"authority_generation,omitempty"`

	// AutoUnseal marks the policy barrier auto-unseal uses.
	AutoUnseal bool `json:"auto_unseal,omitempty"`

	// CreatedAt and UpdatedAt are RFC 3339 timestamps.
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// TPMPolicyCreateRequest creates a named TPM policy of Branches. The values
// of its pcr conditions are read from the tenant's TPM, never supplied by
// the caller.
type TPMPolicyCreateRequest struct {
	TenantID    string            `json:"tenant_id,omitempty"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Branches    []TPMPolicyBranch `json:"branches"`
	AutoUnseal  bool              `json:"auto_unseal,omitempty"`
	OwnerAuth   []byte            `json:"owner_auth,omitempty"`
}

// TPMPolicyDescriptionRequest replaces a TPM policy's description.
type TPMPolicyDescriptionRequest struct {
	TenantID    string `json:"tenant_id,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// TPMPolicyRequest names one TPM policy of a tenant. It is the request of
// get, revoke, verify and objects.
type TPMPolicyRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
	Name     string `json:"name"`
}

// TPMPolicyUpdateRequest updates a TPM policy to its next epoch. Without a
// Branch it re-captures every branch's PCR values from the live PCRs. With
// a Branch, a branch name such as "next", it updates only that branch, to the values
// ReferenceValues, a COSE_Sign1 signed CoRIM, predicts; the CoRIM must
// verify under the server's configured reference signer. ReferenceValues
// is set exactly when Branch is.
type TPMPolicyUpdateRequest struct {
	TenantID        string `json:"tenant_id,omitempty"`
	Name            string `json:"name"`
	Branch          string `json:"branch,omitempty"`
	ReferenceValues []byte `json:"reference_values,omitempty"`
}

// TPMPolicyReference identifies the signed reference values a branch was
// last updated from.
type TPMPolicyReference struct {
	// ID is the CoRIM's identifier, Profile its profile and Signer the name
	// its signer gives itself, each empty when the CoRIM omits it.
	ID      string `json:"id,omitempty"`
	Profile string `json:"profile,omitempty"`
	Signer  string `json:"signer,omitempty"`

	// Digest is the SHA-256 digest of the signed CoRIM.
	Digest []byte `json:"digest"`
}

// TPMPolicyListRequest lists a tenant's TPM policies.
type TPMPolicyListRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
}

// TPMPolicyListResponse contains a tenant's TPM policies, sorted by name.
type TPMPolicyListResponse struct {
	Policies []TPMPolicy `json:"policies"`
}

// TPMPolicyDeleteRequest deletes a TPM policy. It is refused while any
// object is assigned to the policy.
type TPMPolicyDeleteRequest struct {
	TenantID  string `json:"tenant_id,omitempty"`
	Name      string `json:"name"`
	OwnerAuth []byte `json:"owner_auth,omitempty"`
}

// TPMPolicyBranchVerification compares one branch's captured PCR values
// with the live ones.
type TPMPolicyBranchVerification struct {
	// Name is the branch's name.
	Name string `json:"name"`

	// Match reports whether the branch's pcr condition, if it has one,
	// still holds its captured values; Mismatched lists the PCRs that do
	// not, ascending.
	Match      bool   `json:"match"`
	Mismatched []uint `json:"mismatched,omitempty"`

	// Approved reports whether the branch's approval is current, so the
	// branch can be satisfied.
	Approved bool `json:"approved"`

	// Reference identifies the signed reference values the branch is
	// approved for; nil when its values were captured from the live PCRs.
	Reference *TPMPolicyReference `json:"reference,omitempty"`
}

// TPMPolicyVerifyResponse compares a policy's captured PCR values with the
// live ones, branch by branch. It is advisory: the TPM itself enforces the
// policy on use.
type TPMPolicyVerifyResponse struct {
	Name string `json:"name"`

	// Match and Approved report whether every branch matches and holds a
	// current approval.
	Match    bool `json:"match"`
	Approved bool `json:"approved"`

	// Branches reports each branch, index-aligned with the policy's.
	Branches []TPMPolicyBranchVerification `json:"branches"`
}

// TPMPolicyObjectsResponse lists the objects assigned to a policy, as
// "<kind>/<name>" IDs (kind is key or sealed), sorted.
type TPMPolicyObjectsResponse struct {
	Name    string   `json:"name"`
	Objects []string `json:"objects"`
}

// TPMPolicyAutoUnsealRequest sets or clears a policy's auto-unseal mark.
// Setting it clears it from every other policy of the tenant.
type TPMPolicyAutoUnsealRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
}

// TPM object kinds a policy is assigned to.
const (
	// TPMObjectKindKey is a TPM key.
	TPMObjectKindKey = "key"

	// TPMObjectKindSealed is a TPM sealed data object.
	TPMObjectKindSealed = "sealed"
)

// TPMObjectPolicyRequest asks which policy a TPM object was created under.
// KeyID is a key ID or a bare key name; Kind is TPMObjectKindKey (the
// default) or TPMObjectKindSealed.
type TPMObjectPolicyRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
	KeyID    string `json:"key_id"`
	Kind     string `json:"kind,omitempty"`
}

// TPMObjectPolicyResponse reports the policy an object was created under and
// its authPolicy digest (hex) at creation.
type TPMObjectPolicyResponse struct {
	ObjectID   string `json:"object_id"`
	Kind       string `json:"kind"`
	Policy     string `json:"policy"`
	AuthPolicy string `json:"auth_policy,omitempty"`
	CreatedAt  string `json:"created_at"`
}

// TPMAuthorityRotateRequest rotates a tenant's policy authority.
type TPMAuthorityRotateRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
}

// TPMAuthorityRotateResponse describes the policy authority a rotation
// installed.
type TPMAuthorityRotateResponse struct {
	TenantID string `json:"tenant_id,omitempty"`

	// Generation counts rotations; AuthorityName is the new authority's
	// hex-encoded TPM Name, which every approval is now verified against.
	Generation    uint64 `json:"generation"`
	AuthorityName string `json:"authority_name"`

	// Epoch is the revocation counter's current value.
	Epoch uint64 `json:"epoch"`
}

// TenantTPMModeResponse reports a tenant's TPM mode: none, shared or vtpm.
type TenantTPMModeResponse struct {
	TenantID string `json:"tenant_id"`
	Mode     string `json:"mode"`
}

// SetTenantTPMModeRequest changes a tenant's TPM mode. It is refused while
// the tenant's scope holds objects or policies, which cannot move between
// TPMs.
type SetTenantTPMModeRequest struct {
	TenantID  string `json:"tenant_id"`
	Mode      string `json:"mode"`
	OwnerAuth []byte `json:"owner_auth,omitempty"`
}

// TenantVTPMStatusResponse reports a vtpm-mode tenant's virtual TPM.
type TenantVTPMStatusResponse struct {
	TenantID string `json:"tenant_id"`
	Running  bool   `json:"running"`
	PID      int    `json:"pid,omitempty"`
	Socket   string `json:"socket,omitempty"`
	Restarts int64  `json:"restarts,omitempty"`
}

// Algorithm discovery types are aliased from pkg/types, which is where the
// discovery logic (xkms.DiscoverAlgorithms) already builds them. Redefining
// them here would fork the wire shape from the one the server emits.
type (
	// AlgorithmInfo describes one algorithm and the backends providing it.
	AlgorithmInfo = types.AlgorithmInfo

	// AlgorithmsResponse groups the supported algorithms by purpose.
	AlgorithmsResponse = types.AlgorithmsResponse
)
