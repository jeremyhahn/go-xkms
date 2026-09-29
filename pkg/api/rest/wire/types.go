// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package wire

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
	// KeySpec describes the kind of key these parameters accept, as the
	// backend named it; a caller carries it back into the wrap.
	KeySpec string `json:"key_spec,omitempty"`
}

// WrapKeyRequest represents a request to wrap key material.
// Backend names the backend whose wrapping semantics are used and is
// required: wrapping is backend specific, so the caller must state which
// backend the material is being prepared for.
type WrapKeyRequest struct {
	Backend              string `json:"backend"`
	KeyMaterial          []byte `json:"key_material"`
	WrappingPublicKeyPEM string `json:"wrapping_public_key_pem"`
	ImportToken          []byte `json:"import_token,omitempty"`
	Algorithm            string `json:"algorithm"`
	// KeySpec names the kind of key the import parameters were issued for,
	// as the backend named it; an AWS-KMS-style ceremony carries it back.
	KeySpec string `json:"key_spec,omitempty"`
}

// WrapKeyResponse represents the response for wrapping key material.
type WrapKeyResponse struct {
	WrappedKey  []byte `json:"wrapped_key"`
	Algorithm   string `json:"algorithm"`
	ImportToken []byte `json:"import_token,omitempty"`
	// Metadata carries backend-specific information about the wrapped key.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// UnwrapKeyRequest represents a request to unwrap key material.
// Backend names the backend that performs the unwrap and is required: it
// must be the same backend that produced the wrapped material, because
// wrapping semantics differ between backends.
type UnwrapKeyRequest struct {
	Backend              string `json:"backend"`
	WrappedKey           []byte `json:"wrapped_key"`
	WrappingPublicKeyPEM string `json:"wrapping_public_key_pem"`
	ImportToken          []byte `json:"import_token,omitempty"`
	Algorithm            string `json:"algorithm"`
	// KeySpec names the kind of key the material is, as the import
	// parameters named it.
	KeySpec string `json:"key_spec,omitempty"`
	// Metadata carries backend-specific information about the wrapped key.
	Metadata map[string]string `json:"metadata,omitempty"`
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
	// Partition names the sub-namespace the imported key is stored in, as it
	// does for the generate path.
	Partition string `json:"partition,omitempty"`
	// Metadata carries backend-specific information about the wrapped key
	// through to the backend's ImportKey.
	Metadata map[string]string `json:"metadata,omitempty"`
	// Exportable records whether the imported key may leave the backend
	// again; unset keeps the write-once default (symmetric exportable,
	// asymmetric not). See transport.ImportKeyRequest.
	Exportable *bool `json:"exportable,omitempty"`
	// Sensitive carries PKCS#11 CKA_SENSITIVE, as GenerateKeyRequest does.
	Sensitive bool `json:"sensitive,omitempty"`
}

// ImportKeyResponse represents the response for importing a key.
type ImportKeyResponse struct {
	Success      bool   `json:"success"`
	KeyID        string `json:"key_id"`
	Message      string `json:"message,omitempty"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
}
