// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package transport

import "time"

// HealthResponse contains health check information.
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
	Message string `json:"message,omitempty"`
}

// BackendInfo contains information about a backend.
type BackendInfo struct {
	ID             string                 `json:"id"`
	Type           string                 `json:"type"`
	HardwareBacked bool                   `json:"hardware_backed"`
	Capabilities   map[string]interface{} `json:"capabilities,omitempty"`
}

// ListBackendsResponse contains a list of backends.
type ListBackendsResponse struct {
	Backends []BackendInfo `json:"backends"`
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

// ListKeysResponse contains a list of keys.
type ListKeysResponse struct {
	Keys []KeyInfo `json:"keys"`
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
}

// SealResponse contains the sealed data.
type SealResponse struct {
	Backend    string `json:"backend"`
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce,omitempty"`
	Tag        []byte `json:"tag,omitempty"`
}

// UnsealRequest contains parameters for unsealing data.
type UnsealRequest struct {
	Backend    string `json:"backend"`
	KeyID      string `json:"key_id"`
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce,omitempty"`
	Tag        []byte `json:"tag,omitempty"`
	AAD        []byte `json:"aad,omitempty"` // Additional Authenticated Data
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
}

// ImportKeyRequest contains parameters for importing a key.
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
}

// RotateKeyResponse contains the result of key rotation.
type RotateKeyResponse struct {
	Success      bool   `json:"success"`
	KeyID        string `json:"key_id"`
	Message      string `json:"message,omitempty"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
}

// KeyVersion represents a specific version of a key.
type KeyVersion struct {
	Version   uint64 `json:"version"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	CreatedBy string `json:"created_by,omitempty"`
}

// ListKeyVersionsRequest contains parameters for listing key versions.
type ListKeyVersionsRequest struct {
	Backend string `json:"backend"`
	KeyID   string `json:"key_id"`
}

// ListKeyVersionsResponse contains the list of key versions.
type ListKeyVersionsResponse struct {
	KeyID    string        `json:"key_id"`
	Versions []*KeyVersion `json:"versions"`
	Total    int           `json:"total"`
}

// EnableKeyVersionRequest contains parameters for enabling a key version.
type EnableKeyVersionRequest struct {
	Backend string `json:"backend"`
	KeyID   string `json:"key_id"`
	Version uint64 `json:"version"`
}

// EnableKeyVersionResponse contains the result of enabling a key version.
type EnableKeyVersionResponse struct {
	KeyID   string `json:"key_id"`
	Version uint64 `json:"version"`
	Status  string `json:"status"`
}

// DisableKeyVersionRequest contains parameters for disabling a key version.
type DisableKeyVersionRequest struct {
	Backend string `json:"backend"`
	KeyID   string `json:"key_id"`
	Version uint64 `json:"version"`
}

// DisableKeyVersionResponse contains the result of disabling a key version.
type DisableKeyVersionResponse struct {
	KeyID   string `json:"key_id"`
	Version uint64 `json:"version"`
	Status  string `json:"status"`
}

// EnableAllKeyVersionsRequest contains parameters for enabling all key versions.
type EnableAllKeyVersionsRequest struct {
	Backend string `json:"backend"`
	KeyID   string `json:"key_id"`
}

// EnableAllKeyVersionsResponse contains the result of enabling all key versions.
type EnableAllKeyVersionsResponse struct {
	KeyID   string `json:"key_id"`
	Count   int    `json:"count"`
	Message string `json:"message,omitempty"`
}

// DisableAllKeyVersionsRequest contains parameters for disabling all key versions.
type DisableAllKeyVersionsRequest struct {
	Backend string `json:"backend"`
	KeyID   string `json:"key_id"`
}

// DisableAllKeyVersionsResponse contains the result of disabling all key versions.
type DisableAllKeyVersionsResponse struct {
	KeyID   string `json:"key_id"`
	Count   int    `json:"count"`
	Message string `json:"message,omitempty"`
}

// GetImportParametersRequest contains parameters for getting import parameters.
type GetImportParametersRequest struct {
	Backend   string `json:"backend"`
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	KeyType   string `json:"key_type,omitempty"`
	KeySize   int    `json:"key_size,omitempty"`
	Curve     string `json:"curve,omitempty"`
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

// ListCertificatesResponse contains a list of certificates.
type ListCertificatesResponse struct {
	Certificates []CertificateInfo `json:"certificates"`
}

// SaveCertificateChainRequest contains parameters for saving a certificate chain.
type SaveCertificateChainRequest struct {
	Backend  string   `json:"backend"`
	KeyID    string   `json:"key_id"`
	ChainPEM []string `json:"chain_pem"`
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

// ListUsersResponse contains a list of users.
type ListUsersResponse struct {
	Users []UserInfo `json:"users"`
}

// GetUserResponse contains user information.
type GetUserResponse struct {
	User UserInfo `json:"user"`
}

// ListUserCredentialsResponse contains a list of user credentials.
type ListUserCredentialsResponse struct {
	Credentials []CredentialInfo `json:"credentials"`
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
