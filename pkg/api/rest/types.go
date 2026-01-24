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

package rest

import (
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// HealthResponse represents the health check response.
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
}

// BackendInfo represents information about a backend.
type BackendInfo struct {
	ID             string             `json:"id"`
	Type           string             `json:"type"`
	HardwareBacked bool               `json:"hardware_backed"`
	Capabilities   types.Capabilities `json:"capabilities"`
}

// ListBackendsResponse represents the response for listing backends.
type ListBackendsResponse struct {
	Backends []BackendInfo `json:"backends"`
}

// GenerateKeyRequest represents a key generation request.
type GenerateKeyRequest struct {
	KeyID      string `json:"key_id"`
	Backend    string `json:"backend,omitempty"` // Optional, defaults to default backend
	KeyType    string `json:"key_type"`          // "rsa", "ecdsa", "ed25519", "symmetric"
	KeySize    int    `json:"key_size,omitempty"`
	Curve      string `json:"curve,omitempty"`
	Hash       string `json:"hash,omitempty"`
	Algorithm  string `json:"algorithm,omitempty"` // "aes-128-gcm", "aes-192-gcm", "aes-256-gcm"
	Exportable bool   `json:"exportable,omitempty"`
}

// GenerateKeyResponse represents the response for key generation.
type GenerateKeyResponse struct {
	KeyID        string `json:"key_id"`
	KeyType      string `json:"key_type"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	Message      string `json:"message,omitempty"`
}

// KeyInfo represents information about a key.
type KeyInfo struct {
	KeyID        string `json:"key_id"`
	KeyType      string `json:"key_type"`
	Algorithm    string `json:"algorithm"`
	Backend      string `json:"backend"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
}

// ListKeysResponse represents the response for listing keys.
type ListKeysResponse struct {
	Keys []KeyInfo `json:"keys"`
}

// GetKeyResponse represents the response for getting a key.
type GetKeyResponse struct {
	KeyInfo
}

// SignRequest represents a signing request.
type SignRequest struct {
	Backend string `json:"backend,omitempty"` // Optional, defaults to default backend
	Data    []byte `json:"data"`
	Hash    string `json:"hash,omitempty"`
}

// SignResponse represents the response for a signing operation.
type SignResponse struct {
	Signature []byte `json:"signature"`
	Algorithm string `json:"algorithm,omitempty"`
}

// VerifyRequest represents a verification request.
type VerifyRequest struct {
	Backend   string `json:"backend,omitempty"` // Optional, defaults to default backend
	Data      []byte `json:"data"`
	Signature []byte `json:"signature"`
	Hash      string `json:"hash,omitempty"`
}

// VerifyResponse represents the response for a verification operation.
type VerifyResponse struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message,omitempty"`
}

// DeleteKeyResponse represents the response for key deletion.
type DeleteKeyResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// ErrorResponse represents an error response.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code,omitempty"`
}

// SuccessResponse represents a generic success response.
type SuccessResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// RotateKeyResponse represents the response for key rotation.
type RotateKeyResponse struct {
	Success      bool   `json:"success"`
	KeyID        string `json:"key_id"`
	KeyType      string `json:"key_type"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	Message      string `json:"message,omitempty"`
}

// EncryptRequest represents an encryption request (symmetric encryption).
type EncryptRequest struct {
	Backend        string `json:"backend,omitempty"` // Optional, defaults to default backend
	Plaintext      []byte `json:"plaintext"`
	AdditionalData []byte `json:"additional_data,omitempty"` // Optional AAD for GCM mode
}

// EncryptResponse represents the response for an encryption operation.
type EncryptResponse struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
	Tag        []byte `json:"tag"`
}

// DecryptRequest represents a decryption request.
type DecryptRequest struct {
	Backend        string `json:"backend,omitempty"` // Optional, defaults to default backend
	Ciphertext     []byte `json:"ciphertext"`
	AdditionalData []byte `json:"additional_data,omitempty"` // Optional AAD for symmetric decryption
	Nonce          []byte `json:"nonce,omitempty"`           // Required for symmetric decryption
	Tag            []byte `json:"tag,omitempty"`             // Required for symmetric decryption (GCM)
}

// DecryptResponse represents the response for a decryption operation.
type DecryptResponse struct {
	Plaintext []byte `json:"plaintext"`
}

// EncryptAsymRequest represents an asymmetric encryption request (RSA-OAEP).
type EncryptAsymRequest struct {
	Backend   string `json:"backend,omitempty"` // Optional, defaults to default backend
	Plaintext []byte `json:"plaintext"`
	Hash      string `json:"hash,omitempty"` // Hash algorithm for OAEP (e.g., "sha256")
}

// EncryptAsymResponse represents the response for an asymmetric encryption operation.
type EncryptAsymResponse struct {
	Ciphertext []byte `json:"ciphertext"`
}

// SaveCertRequest represents a request to save a certificate.
type SaveCertRequest struct {
	Backend        string `json:"backend,omitempty"` // Optional, defaults to default backend
	CertificatePEM string `json:"certificate_pem"`
}

// GetCertResponse represents the response for getting a certificate.
type GetCertResponse struct {
	KeyID          string `json:"key_id"`
	CertificatePEM string `json:"certificate_pem"`
}

// CertificateInfo represents information about a stored certificate.
type CertificateInfo struct {
	KeyID          string `json:"key_id"`
	Subject        string `json:"subject,omitempty"`
	Issuer         string `json:"issuer,omitempty"`
	NotBefore      string `json:"not_before,omitempty"`
	NotAfter       string `json:"not_after,omitempty"`
	SerialNumber   string `json:"serial_number,omitempty"`
	CertificatePEM string `json:"certificate_pem,omitempty"`
}

// ListCertsResponse represents the response for listing certificates.
type ListCertsResponse struct {
	Certificates []CertificateInfo `json:"certificates"`
}

// CertExistsResponse represents the response for checking certificate existence.
type CertExistsResponse struct {
	Exists bool `json:"exists"`
}

// SaveCertChainRequest represents a request to save a certificate chain.
type SaveCertChainRequest struct {
	Backend      string   `json:"backend,omitempty"` // Optional, defaults to default backend
	CertChainPEM []string `json:"cert_chain_pem"`
}

// GetCertChainResponse represents the response for getting a certificate chain.
type GetCertChainResponse struct {
	KeyID        string   `json:"key_id"`
	CertChainPEM []string `json:"cert_chain_pem"`
}

// GetTLSCertificateResponse represents the response for getting a TLS certificate.
// Note: For security reasons, the private key is not included in this response.
// Use the GetKey endpoint to retrieve key information if needed.
type GetTLSCertificateResponse struct {
	KeyID          string   `json:"key_id"`
	CertificatePEM string   `json:"certificate_pem"`
	ChainPEM       []string `json:"chain_pem,omitempty"`
}

// GetImportParametersRequest represents a request to get import parameters.
type GetImportParametersRequest struct {
	Backend    string `json:"backend"`
	KeyID      string `json:"key_id"`
	KeyType    string `json:"key_type"`               // "rsa", "ecdsa", "ed25519", "symmetric"
	Algorithm  string `json:"algorithm"`              // Wrapping algorithm
	KeySize    int    `json:"key_size,omitempty"`     // For RSA keys
	Curve      string `json:"curve,omitempty"`        // For ECDSA keys
	Hash       string `json:"hash,omitempty"`         // Hash algorithm
	AESKeySize int    `json:"aes_key_size,omitempty"` // For AES keys (128, 192, 256)
}

// GetImportParametersResponse represents the response for getting import parameters.
type GetImportParametersResponse struct {
	WrappingPublicKeyPEM string `json:"wrapping_public_key_pem"`
	ImportToken          []byte `json:"import_token,omitempty"`
	Algorithm            string `json:"algorithm"`
	ExpiresAt            string `json:"expires_at,omitempty"` // RFC3339 format
}

// WrapKeyRequest represents a request to wrap key material.
type WrapKeyRequest struct {
	KeyMaterial          []byte `json:"key_material"`
	WrappingPublicKeyPEM string `json:"wrapping_public_key_pem"`
	ImportToken          []byte `json:"import_token,omitempty"`
	Algorithm            string `json:"algorithm"`
}

// WrapKeyResponse represents the response for wrapping key material.
type WrapKeyResponse struct {
	WrappedKey  []byte `json:"wrapped_key"`
	Algorithm   string `json:"algorithm"`
	ImportToken []byte `json:"import_token,omitempty"`
}

// UnwrapKeyRequest represents a request to unwrap key material.
type UnwrapKeyRequest struct {
	WrappedKey           []byte `json:"wrapped_key"`
	WrappingPublicKeyPEM string `json:"wrapping_public_key_pem"`
	ImportToken          []byte `json:"import_token,omitempty"`
	Algorithm            string `json:"algorithm"`
}

// UnwrapKeyResponse represents the response for unwrapping key material.
type UnwrapKeyResponse struct {
	KeyMaterial []byte `json:"key_material"`
}

// ImportKeyRequest represents a request to import a key.
type ImportKeyRequest struct {
	Backend     string `json:"backend"`
	KeyID       string `json:"key_id"`
	KeyType     string `json:"key_type"` // "rsa", "ecdsa", "ed25519", "symmetric"
	WrappedKey  []byte `json:"wrapped_key"`
	ImportToken []byte `json:"import_token,omitempty"`
	Algorithm   string `json:"algorithm"`              // Wrapping algorithm
	KeySize     int    `json:"key_size,omitempty"`     // For RSA keys
	Curve       string `json:"curve,omitempty"`        // For ECDSA keys
	Hash        string `json:"hash,omitempty"`         // Hash algorithm
	AESKeySize  int    `json:"aes_key_size,omitempty"` // For AES keys (128, 192, 256)
}

// ImportKeyResponse represents the response for importing a key.
type ImportKeyResponse struct {
	Success      bool   `json:"success"`
	KeyID        string `json:"key_id"`
	Message      string `json:"message,omitempty"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
}

// ExportKeyRequest represents a request to export a key.
type ExportKeyRequest struct {
	Backend   string `json:"backend,omitempty"` // Optional, defaults to default backend
	Algorithm string `json:"algorithm"`         // Wrapping algorithm for export
}

// CopyKeyRequest represents a request to copy a key from one backend to another.
type CopyKeyRequest struct {
	SourceBackend string `json:"source_backend"` // Source backend name
	SourceKeyID   string `json:"source_key_id"`
	DestBackend   string `json:"dest_backend"` // Destination backend name
	DestKeyID     string `json:"dest_key_id"`
	KeyType       string `json:"key_type"`  // "rsa", "ecdsa", "ed25519", "symmetric"
	Algorithm     string `json:"algorithm"` // Wrapping algorithm
	KeySize       int    `json:"key_size,omitempty"`
	Curve         string `json:"curve,omitempty"`
	Hash          string `json:"hash,omitempty"`
	AESKeySize    int    `json:"aes_key_size,omitempty"`
}

// CopyKeyResponse represents the response for copying a key.
type CopyKeyResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// ExportKeyResponse represents the response for exporting a key.
type ExportKeyResponse struct {
	KeyID       string `json:"key_id"`
	WrappedKey  []byte `json:"wrapped_key"`
	Algorithm   string `json:"algorithm"`
	ImportToken []byte `json:"import_token,omitempty"`
}

// KeyVersionInfo represents information about a specific version of a key.
// Used for key versioning operations.
type KeyVersionInfo struct {
	Version     int    `json:"version"`
	State       string `json:"state"`                  // "enabled", "disabled", "destroyed"
	CreatedAt   string `json:"created_at"`             // RFC3339 format
	RotatedAt   string `json:"rotated_at,omitempty"`   // RFC3339 format
	DestroyedAt string `json:"destroyed_at,omitempty"` // RFC3339 format
}

// ListKeyVersionsResponse represents the response for listing key versions.
// This type is prepared for future implementation of key versioning.
type ListKeyVersionsResponse struct {
	KeyID    string           `json:"key_id"`
	Versions []KeyVersionInfo `json:"versions"`
}

// EnableKeyVersionResponse represents the response for enabling a key version.
// This type is prepared for future implementation of key versioning.
type EnableKeyVersionResponse struct {
	KeyID   string `json:"key_id"`
	Version int    `json:"version"`
	State   string `json:"state"`
	Message string `json:"message"`
}

// DisableKeyVersionResponse represents the response for disabling a key version.
// This type is prepared for future implementation of key versioning.
type DisableKeyVersionResponse struct {
	KeyID   string `json:"key_id"`
	Version int    `json:"version"`
	State   string `json:"state"`
	Message string `json:"message"`
}

// EnableAllKeyVersionsResponse represents the response for enabling all key versions.
// This type is prepared for future implementation of key versioning.
type EnableAllKeyVersionsResponse struct {
	KeyID           string `json:"key_id"`
	VersionsEnabled int    `json:"versions_enabled"`
	Message         string `json:"message"`
}

// DisableAllKeyVersionsResponse represents the response for disabling all key versions.
// This type is prepared for future implementation of key versioning.
type DisableAllKeyVersionsResponse struct {
	KeyID            string `json:"key_id"`
	VersionsDisabled int    `json:"versions_disabled"`
	Message          string `json:"message"`
}

// SealRequest represents a request to seal data.
// Sealing encrypts data using a backend's sealing mechanism, which may include
// hardware-backed protection (TPM, HSM) or policy-based access control.
type SealRequest struct {
	Backend string `json:"backend"`          // Backend to use for sealing
	KeyID   string `json:"key_id,omitempty"` // Optional key ID for sealing key
	Data    []byte `json:"data"`             // Data to seal (base64 encoded in JSON)
	AAD     []byte `json:"aad,omitempty"`    // Additional Authenticated Data (base64 encoded)
}

// SealResponse represents the response from a seal operation.
type SealResponse struct {
	Backend    string            `json:"backend"`            // Backend that performed the sealing
	Ciphertext []byte            `json:"ciphertext"`         // Encrypted data (base64 encoded)
	Nonce      []byte            `json:"nonce,omitempty"`    // Nonce/IV if applicable (base64 encoded)
	Tag        []byte            `json:"tag,omitempty"`      // Authentication tag if applicable (base64 encoded)
	Metadata   map[string][]byte `json:"metadata,omitempty"` // Backend-specific metadata
}

// UnsealRequest represents a request to unseal data.
// The sealed data must have been created by the same backend type.
type UnsealRequest struct {
	Backend    string            `json:"backend"`            // Backend to use for unsealing
	KeyID      string            `json:"key_id,omitempty"`   // Optional key ID for unsealing key
	Ciphertext []byte            `json:"ciphertext"`         // Encrypted data (base64 encoded)
	Nonce      []byte            `json:"nonce,omitempty"`    // Nonce/IV if applicable (base64 encoded)
	Tag        []byte            `json:"tag,omitempty"`      // Authentication tag if applicable (base64 encoded)
	AAD        []byte            `json:"aad,omitempty"`      // Additional Authenticated Data (base64 encoded)
	Metadata   map[string][]byte `json:"metadata,omitempty"` // Backend-specific metadata from seal response
}

// UnsealResponse represents the response from an unseal operation.
type UnsealResponse struct {
	Plaintext []byte `json:"plaintext"` // Decrypted data (base64 encoded)
}

// CanSealResponse represents the response for checking sealing capability.
type CanSealResponse struct {
	CanSeal bool   `json:"can_seal"`          // Whether the backend supports sealing
	Backend string `json:"backend,omitempty"` // Backend that was checked
}
