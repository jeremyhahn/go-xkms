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

package mcp

import (
	"encoding/json"
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

// ListBackendsResult represents the result of listing backends
type ListBackendsResult struct {
	Backends []string `json:"backends"`
}

// GenerateKeyParams represents parameters for key generation
type GenerateKeyParams struct {
	KeyID     string `json:"key_id"`
	Backend   string `json:"backend"`
	KeyType   string `json:"key_type"`
	KeySize   int    `json:"key_size,omitempty"`
	Curve     string `json:"curve,omitempty"`
	Algorithm string `json:"algorithm,omitempty"` // For AES: "aes128-gcm", "aes192-gcm", "aes256-gcm"
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
}

// SignParams represents parameters for signing
type SignParams struct {
	KeyID   string `json:"key_id"`
	Backend string `json:"backend"`
	Data    []byte `json:"data"`
	Hash    string `json:"hash"`
}

// SignResult represents the result of signing
type SignResult struct {
	Signature interface{} `json:"signature"`
}

// VerifyParams represents parameters for verification
type VerifyParams struct {
	KeyID     string      `json:"key_id"`
	Backend   string      `json:"backend"`
	Data      []byte      `json:"data"`
	Signature interface{} `json:"signature"`
	Hash      string      `json:"hash"`
}

// VerifyResult represents the result of verification
type VerifyResult struct {
	Valid bool `json:"valid"`
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
}

// DecryptParams represents parameters for decryption
type DecryptParams struct {
	KeyID          string `json:"key_id"`
	Backend        string `json:"backend"`
	Ciphertext     []byte `json:"ciphertext"`
	Nonce          []byte `json:"nonce,omitempty"`           // For symmetric decryption
	Tag            []byte `json:"tag,omitempty"`             // For symmetric decryption
	AdditionalData []byte `json:"additional_data,omitempty"` // For symmetric decryption with AAD
}

// DecryptResult represents the result of decryption
type DecryptResult struct {
	Plaintext []byte `json:"plaintext"`
}

// EncryptParams represents parameters for encryption
type EncryptParams struct {
	KeyID          string `json:"key_id"`
	Backend        string `json:"backend"`
	Plaintext      []byte `json:"plaintext"`
	AdditionalData []byte `json:"additional_data,omitempty"` // For AEAD (authenticated encryption with associated data)
}

// EncryptResult represents the result of encryption
type EncryptResult struct {
	Ciphertext []byte `json:"ciphertext"` // base64 encoded in JSON
	Nonce      []byte `json:"nonce"`      // base64 encoded in JSON
	Tag        []byte `json:"tag"`        // base64 encoded in JSON
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
	KeyIDs []string `json:"key_ids"`
}

// CertExistsParams represents parameters for checking certificate existence
type CertExistsParams struct {
	KeyID string `json:"key_id"`
}

// CertExistsResult represents the result of checking certificate existence
type CertExistsResult struct {
	Exists bool `json:"exists"`
}

// ListKeysResult represents the result of listing keys
type ListKeysResult struct {
	Keys []KeyInfo `json:"keys"`
}

// KeyInfo represents basic information about a key
type KeyInfo struct {
	CN string `json:"cn"`
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

// GetTLSCertificateResult represents the result of getting a TLS certificate
type GetTLSCertificateResult struct {
	CertPEM        string   `json:"cert_pem"`
	ChainPEMs      []string `json:"chain_pems,omitempty"`
	PrivateKeyType string   `json:"private_key_type"`
}

// GetImportParametersParams represents parameters for getting import parameters
type GetImportParametersParams struct {
	KeyID     string `json:"key_id"`
	Backend   string `json:"backend"`
	Algorithm string `json:"algorithm"` // Wrapping algorithm
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
	KeyMaterial          []byte `json:"key_material"`
	WrappingPublicKeyPEM string `json:"wrapping_public_key_pem"`
	ImportToken          []byte `json:"import_token,omitempty"`
	Algorithm            string `json:"algorithm"`
}

// WrapKeyResult represents the wrapped key response
type WrapKeyResult struct {
	WrappedKey  []byte            `json:"wrapped_key"`
	Algorithm   string            `json:"algorithm"`
	ImportToken []byte            `json:"import_token,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// ImportKeyParams represents parameters for importing key material
type ImportKeyParams struct {
	KeyID       string            `json:"key_id"`
	Backend     string            `json:"backend"`
	WrappedKey  []byte            `json:"wrapped_key"`
	Algorithm   string            `json:"algorithm"`
	ImportToken []byte            `json:"import_token,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
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
}

// AsymmetricEncryptResult represents the result of asymmetric encryption
type AsymmetricEncryptResult struct {
	Ciphertext []byte `json:"ciphertext"`
}

// AsymmetricDecryptParams represents parameters for asymmetric decryption (RSA)
type AsymmetricDecryptParams struct {
	KeyID      string `json:"key_id"`
	Backend    string `json:"backend"`
	Ciphertext []byte `json:"ciphertext"`
}

// AsymmetricDecryptResult represents the result of asymmetric decryption
type AsymmetricDecryptResult struct {
	Plaintext []byte `json:"plaintext"`
}

// CopyKeyParams represents parameters for copying a key from one backend to another
type CopyKeyParams struct {
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

// CopyKeyResult represents the result of copying a key
type CopyKeyResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}
