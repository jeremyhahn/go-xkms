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
	KeyID     string `json:"key_id"`
	Backend   string `json:"backend,omitempty"` // Optional, defaults to default backend
	KeyType   string `json:"key_type"`          // "rsa", "ecdsa", "ed25519", "aes"
	KeySize   int    `json:"key_size,omitempty"`
	Curve     string `json:"curve,omitempty"`
	Hash      string `json:"hash,omitempty"`
	Algorithm string `json:"algorithm,omitempty"` // "aes-128-gcm", "aes-192-gcm", "aes-256-gcm"
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

// ListCertsResponse represents the response for listing certificates.
type ListCertsResponse struct {
	Certificates []string `json:"certificates"`
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
	KeyType    string `json:"key_type"`               // "rsa", "ecdsa", "ed25519", "aes"
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
	KeyType     string `json:"key_type"` // "rsa", "ecdsa", "ed25519", "aes"
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
	KeyType       string `json:"key_type"`  // "rsa", "ecdsa", "ed25519", "aes"
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
