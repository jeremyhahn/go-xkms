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
	Hash    string `json:"hash,omitempty"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// SignResponse contains the signature.
type SignResponse struct {
	Signature []byte `json:"signature"`
	Algorithm string `json:"algorithm,omitempty"`
}

// VerifyRequest contains parameters for signature verification.
type VerifyRequest struct {
	Backend   string `json:"backend"`
	KeyID     string `json:"key_id"`
	Data      []byte `json:"data"`
	Signature []byte `json:"signature"`
	Hash      string `json:"hash,omitempty"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// VerifyResponse contains the verification result.
type VerifyResponse struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message,omitempty"`
}

// EncryptRequest contains parameters for encryption.
type EncryptRequest struct {
	Backend        string `json:"backend"`
	KeyID          string `json:"key_id"`
	Plaintext      []byte `json:"plaintext"`
	AdditionalData []byte `json:"additional_data,omitempty"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// EncryptResponse contains the encrypted data.
type EncryptResponse struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce,omitempty"`
	Tag        []byte `json:"tag,omitempty"`
}

// DecryptRequest contains parameters for decryption.
type DecryptRequest struct {
	Backend        string `json:"backend"`
	KeyID          string `json:"key_id"`
	Ciphertext     []byte `json:"ciphertext"`
	Nonce          []byte `json:"nonce,omitempty"`
	Tag            []byte `json:"tag,omitempty"`
	AdditionalData []byte `json:"additional_data,omitempty"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// DecryptResponse contains the decrypted data.
type DecryptResponse struct {
	Plaintext []byte `json:"plaintext"`
}

// EncryptAsymRequest contains parameters for asymmetric encryption.
type EncryptAsymRequest struct {
	Backend   string `json:"backend"`
	KeyID     string `json:"key_id"`
	Plaintext []byte `json:"plaintext"`
	Hash      string `json:"hash,omitempty"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// EncryptAsymResponse contains the encrypted data from asymmetric encryption.
type EncryptAsymResponse struct {
	Ciphertext []byte `json:"ciphertext"`
}

// SealRequest contains parameters for sealing data.
type SealRequest struct {
	Backend string `json:"backend"`
	KeyID   string `json:"key_id"`
	Data    []byte `json:"data"`
	AAD     []byte `json:"aad,omitempty"` // Additional Authenticated Data
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`

	// PCRs specifies TPM Platform Configuration Register indices to bind sealed data to.
	// The data can only be unsealed when these PCRs have the same values.
	PCRs []int `json:"pcrs,omitempty"`

	// PCRHashAlg specifies the hash algorithm for PCR policy (e.g., "SHA256").
	// Defaults to SHA-256 if PCRs are specified but this is empty.
	PCRHashAlg string `json:"pcr_hash_alg,omitempty"`

	// Password provides authentication for the sealed object (TPM-specific).
	// This is the UserAuth value set during sealing.
	Password string `json:"password,omitempty"`
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
	Password string `json:"password,omitempty"`
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

// RotateKeyResponse contains the result of key rotation.
type RotateKeyResponse struct {
	Success      bool   `json:"success"`
	KeyID        string `json:"key_id"`
	Message      string `json:"message,omitempty"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
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
}

// WrapKeyRequest contains parameters for wrapping a key.
type WrapKeyRequest struct {
	Backend           string `json:"backend"`
	KeyMaterial       []byte `json:"key_material"`
	Algorithm         string `json:"algorithm"`
	WrappingPublicKey []byte `json:"wrapping_public_key,omitempty"`
	ImportToken       []byte `json:"import_token,omitempty"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// WrapKeyResponse contains the wrapped key.
type WrapKeyResponse struct {
	WrappedKeyMaterial []byte `json:"wrapped_key_material"`
	Algorithm          string `json:"algorithm"`
}

// UnwrapKeyRequest contains parameters for unwrapping a key.
type UnwrapKeyRequest struct {
	Backend            string `json:"backend"`
	WrappedKeyMaterial []byte `json:"wrapped_key_material"`
	Algorithm          string `json:"algorithm"`
	ImportToken        []byte `json:"import_token,omitempty"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// UnwrapKeyResponse contains the unwrapped key.
type UnwrapKeyResponse struct {
	KeyMaterial []byte `json:"key_material"`
}

// CopyKeyRequest contains parameters for copying a key.
type CopyKeyRequest struct {
	SourceBackend string `json:"source_backend"`
	SourceKeyID   string `json:"source_key_id"`
	DestBackend   string `json:"dest_backend"`
	DestKeyID     string `json:"dest_key_id"`
	Algorithm     string `json:"algorithm"`
	KeyType       string `json:"key_type,omitempty"`
	KeySize       int    `json:"key_size,omitempty"`
	Curve         string `json:"curve,omitempty"`
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

// GetTLSCertificateResponse contains a TLS certificate bundle.
type GetTLSCertificateResponse struct {
	KeyID          string `json:"key_id"`
	PrivateKeyPEM  string `json:"private_key_pem,omitempty"`
	CertificatePEM string `json:"certificate_pem"`
	ChainPEM       string `json:"chain_pem,omitempty"`
}

// UserInfo contains information about a user.
type UserInfo struct {
	Username    string     `json:"username"`
	DisplayName string     `json:"display_name,omitempty"`
	Role        string     `json:"role,omitempty"`
	Enabled     bool       `json:"enabled"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLogin   *time.Time `json:"last_login,omitempty"`
}

// CredentialInfo contains information about a user credential.
type CredentialInfo struct {
	ID          string     `json:"id"`
	DisplayName string     `json:"display_name,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsed    *time.Time `json:"last_used,omitempty"`
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

// GetUserResponse contains user information.
type GetUserResponse struct {
	User UserInfo `json:"user"`
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

// Authentication flow types for FIDO2/WebAuthn server-side operations

// BeginRegistrationRequest contains parameters to begin a WebAuthn registration.
type BeginRegistrationRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	RPID        string `json:"rp_id"`
	RPName      string `json:"rp_name"`
}

// BeginRegistrationResponse contains the challenge and options for WebAuthn registration.
type BeginRegistrationResponse struct {
	Challenge        string            `json:"challenge"`         // base64 encoded
	UserID           string            `json:"user_id"`           // base64 encoded
	RPID             string            `json:"rp_id"`             // Relying Party ID
	RPName           string            `json:"rp_name"`           // Relying Party Name
	CredentialParams []CredentialParam `json:"credential_params"` // Allowed credential types
}

// CredentialParam represents a WebAuthn credential type and algorithm.
type CredentialParam struct {
	Type string `json:"type"` // e.g., "public-key"
	Alg  int    `json:"alg"`  // COSE algorithm identifier (e.g., -7 for ES256)
}

// FinishRegistrationRequest contains the authenticator response to complete registration.
type FinishRegistrationRequest struct {
	Username        string `json:"username"`
	CredentialID    string `json:"credential_id"`    // base64 encoded
	PublicKey       string `json:"public_key"`       // base64 encoded COSE key
	AttestationData string `json:"attestation_data"` // base64 encoded
	ClientDataJSON  string `json:"client_data_json"` // base64 encoded
}

// FinishRegistrationResponse contains the result of WebAuthn registration.
type FinishRegistrationResponse struct {
	Success      bool   `json:"success"`
	CredentialID string `json:"credential_id"`
	Message      string `json:"message,omitempty"`
}

// BeginAuthenticationRequest contains parameters to begin a WebAuthn authentication.
type BeginAuthenticationRequest struct {
	Username string `json:"username"`
	RPID     string `json:"rp_id"`
}

// BeginAuthenticationResponse contains the challenge and options for WebAuthn authentication.
type BeginAuthenticationResponse struct {
	Challenge     string   `json:"challenge"`      // base64 encoded
	RPID          string   `json:"rp_id"`          // Relying Party ID
	CredentialIDs []string `json:"credential_ids"` // base64 encoded allowed credential IDs
}

// FinishAuthenticationRequest contains the authenticator response to complete authentication.
type FinishAuthenticationRequest struct {
	Username          string `json:"username"`
	CredentialID      string `json:"credential_id"`      // base64 encoded
	Signature         string `json:"signature"`          // base64 encoded
	AuthenticatorData string `json:"authenticator_data"` // base64 encoded
	ClientDataJSON    string `json:"client_data_json"`   // base64 encoded
}

// FinishAuthenticationResponse contains the result of WebAuthn authentication.
type FinishAuthenticationResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token,omitempty"` // JWT token
	Message string `json:"message,omitempty"`
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
	KDFInfo []byte `json:"kdf_info,omitempty"`

	// KeyLength specifies the desired output key length in bytes
	// Common values: 16 (AES-128), 32 (AES-256). Defaults to 32
	KeyLength int `json:"key_length,omitempty"`

	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// DeriveKeyECDHResponse contains the derived key from ECDH key agreement.
type DeriveKeyECDHResponse struct {
	// DerivedKey is the key material derived from ECDH + KDF
	DerivedKey []byte `json:"derived_key"`
}

// WrapKeyByIDRequest contains parameters for wrapping a key using another key.
// Both keys are identified by their IDs (server-side key wrap).
type WrapKeyByIDRequest struct {
	// WrappingKeyID is the ID of the key used for wrapping (Key Encryption Key)
	WrappingKeyID string `json:"wrapping_key_id"`

	// WrappingKeyBackend is the backend containing the wrapping key
	WrappingKeyBackend string `json:"wrapping_key_backend"`

	// TargetKeyID is the ID of the key to be wrapped (must be extractable)
	TargetKeyID string `json:"target_key_id"`

	// TargetKeyBackend is the backend containing the target key
	TargetKeyBackend string `json:"target_key_backend"`

	// Algorithm specifies the wrapping algorithm
	// Supported: "RSAES_OAEP_SHA_256", "AES_KEY_WRAP", etc.
	Algorithm string `json:"algorithm"`

	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// WrapKeyByIDResponse contains the wrapped key material from server-side wrap.
type WrapKeyByIDResponse struct {
	// WrappedKey is the encrypted key material
	WrappedKey []byte `json:"wrapped_key"`

	// Algorithm is the algorithm used for wrapping
	Algorithm string `json:"algorithm"`
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
	// KeyMaterial is the raw key bytes (plaintext symmetric key material)
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
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// GeneratePIVKeyResponse contains the result of PIV key generation.
type GeneratePIVKeyResponse struct {
	Slot        string `json:"slot"`
	Certificate []byte `json:"certificate"` // Self-signed cert PEM
	PublicKey   []byte `json:"public_key"`
}

// GeneratePIVCSRRequest contains parameters for generating a PIV CSR.
type GeneratePIVCSRRequest struct {
	Backend string `json:"backend"`
	Slot    string `json:"slot"`
	Subject string `json:"subject"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// GeneratePIVCSRResponse contains the generated CSR.
type GeneratePIVCSRResponse struct {
	Slot string `json:"slot"`
	CSR  []byte `json:"csr"` // PEM-encoded
}

// Barrier Operations

// BarrierInitializeRequest contains parameters for initializing the barrier
// with a single master key.
type BarrierInitializeRequest struct {
	Secret string `json:"secret"`
}

// BarrierUnsealRequest contains parameters for unsealing the barrier.
type BarrierUnsealRequest struct {
	Secret string `json:"secret"`
}

// BarrierStatusResponse contains the current barrier status.
type BarrierStatusResponse struct {
	Sealed         bool   `json:"sealed"`
	Strategy       string `json:"strategy"`
	HardwareBacked bool   `json:"hardware_backed"`
	InitializedAt  string `json:"initialized_at,omitempty"`
}

// BarrierInitializeShamirRequest contains parameters for initializing
// the barrier using Shamir secret sharing.
type BarrierInitializeShamirRequest struct {
	Secret      string `json:"secret"`
	Threshold   int    `json:"threshold"`
	TotalShares int    `json:"total_shares"`
}

// BarrierInitializeShamirResponse contains the generated Shamir shares.
type BarrierInitializeShamirResponse struct {
	Shares      []string `json:"shares"`
	Threshold   int      `json:"threshold"`
	TotalShares int      `json:"total_shares"`
}

// BarrierUnsealShareRequest contains a single Shamir share for unsealing.
type BarrierUnsealShareRequest struct {
	Share string `json:"share"`
}

// BarrierUnsealShareResponse contains the unseal progress after submitting a share.
type BarrierUnsealShareResponse struct {
	Required  int  `json:"required"`
	Submitted int  `json:"submitted"`
	Complete  bool `json:"complete"`
}

// BarrierUnsealSharesRequest contains multiple Shamir shares for unsealing
// in a single request.
type BarrierUnsealSharesRequest struct {
	Shares []string `json:"shares"`
}

// BarrierShamirSharesResponse contains metadata about stored Shamir shares.
type BarrierShamirSharesResponse struct {
	Count     int `json:"count"`
	Threshold int `json:"threshold"`
	Total     int `json:"total"`
}

// BarrierShamirDeleteShareRequest identifies a Shamir share to delete by index.
type BarrierShamirDeleteShareRequest struct {
	Index int `json:"index"`
}

// BarrierRekeyRequest contains parameters for rekeying the barrier with
// new Shamir shares.
type BarrierRekeyRequest struct {
	Threshold int `json:"threshold"`
	Total     int `json:"total"`
}

// BarrierRekeyResponse contains the new Shamir shares after rekeying.
type BarrierRekeyResponse struct {
	Shares      []string `json:"shares"`
	Threshold   int      `json:"threshold"`
	TotalShares int      `json:"total_shares"`
}

// BarrierGenerateRecoveryKeysRequest contains parameters for generating
// recovery keys.
type BarrierGenerateRecoveryKeysRequest struct {
	Threshold int `json:"threshold"`
	Total     int `json:"total"`
}

// BarrierRecoveryKeysResponse contains the generated recovery keys.
type BarrierRecoveryKeysResponse struct {
	Keys      []string `json:"keys"`
	Threshold int      `json:"threshold"`
	Total     int      `json:"total"`
}

// BarrierRecoverWithKeysRequest contains recovery keys for unsealing.
type BarrierRecoverWithKeysRequest struct {
	Keys []string `json:"keys"`
}

// BarrierHasRecoveryKeysResponse indicates whether recovery keys exist.
type BarrierHasRecoveryKeysResponse struct {
	HasKeys bool `json:"has_keys"`
}

// BarrierGenerateRootTokenRequest contains Shamir shares for generating
// a root token.
type BarrierGenerateRootTokenRequest struct {
	Shares []string `json:"shares"`
}

// BarrierRootTokenResponse contains the generated root token.
type BarrierRootTokenResponse struct {
	Token     string `json:"token"`
	CreatedAt string `json:"created_at"`
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
	Decrypt  bool   `json:"decrypt,omitempty"`
	UserPIN  string `json:"user_pin,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
}

// PasswordGetResponse contains a password entry.
type PasswordGetResponse struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
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

// PasswordStoreUnlockRequest contains parameters for unlocking the password store.
type PasswordStoreUnlockRequest struct {
	UserPIN string `json:"user_pin"`
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

// PCR Policy Operations

// PolicyCreateRequest contains parameters for creating a PCR policy.
type PolicyCreateRequest struct {
	Name string `json:"name"`
	Bank string `json:"bank"`
	PCRs []int  `json:"pcrs"`
}

// PolicyCreateResponse contains the result of creating a policy.
type PolicyCreateResponse struct {
	Name      string         `json:"name"`
	Bank      string         `json:"bank"`
	PCRs      []int          `json:"pcrs"`
	Values    map[int]string `json:"values"`
	CreatedAt string         `json:"created_at"`
}

// PolicyGetRequest contains parameters for retrieving a policy.
type PolicyGetRequest struct {
	Name string `json:"name"`
}

// PolicyGetResponse contains a policy definition.
type PolicyGetResponse struct {
	Name      string         `json:"name"`
	Bank      string         `json:"bank"`
	PCRs      []int          `json:"pcrs"`
	Values    map[int]string `json:"values"`
	CreatedAt string         `json:"created_at"`
	UpdatedAt string         `json:"updated_at,omitempty"`
}

// PolicyListResponse contains a list of policies.
type PolicyListResponse struct {
	Policies []PolicyGetResponse `json:"policies"`
	PageResponse
}

// PolicyDeleteRequest contains parameters for deleting a policy.
type PolicyDeleteRequest struct {
	Name string `json:"name"`
}

// PolicyRefreshRequest contains parameters for refreshing a policy.
type PolicyRefreshRequest struct {
	Name string `json:"name"`
}

// PolicyVerifyRequest contains parameters for verifying a policy.
type PolicyVerifyRequest struct {
	Name string `json:"name"`
}

// PolicyVerifyResponse contains the result of verifying a policy.
type PolicyVerifyResponse struct {
	Name    string `json:"name"`
	Valid   bool   `json:"valid"`
	Message string `json:"message,omitempty"`
}

// PolicyExportRequest contains parameters for exporting a policy.
type PolicyExportRequest struct {
	Name string `json:"name"`
}

// PolicyExportResponse contains the exported policy data.
type PolicyExportResponse struct {
	Data string `json:"data"`
}
