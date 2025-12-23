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

//go:build integration
// +build integration

package keychain

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TestKeyID_NewKeyID tests creating Key IDs
func TestKeyID_NewKeyID(t *testing.T) {
	tests := []struct {
		name        string
		backend     string
		keyType     string
		algo        string
		keyname     string
		expectError bool
	}{
		{
			name:        "ValidRSA",
			backend:     "software",
			keyType:     "signing",
			algo:        "rsa",
			keyname:     "my-key",
			expectError: false,
		},
		{
			name:        "ValidECDSA",
			backend:     "software",
			keyType:     "signing",
			algo:        "ecdsa-p256",
			keyname:     "my-ecdsa-key",
			expectError: false,
		},
		{
			name:        "ValidEd25519",
			backend:     "software",
			keyType:     "signing",
			algo:        "ed25519",
			keyname:     "my-ed25519-key",
			expectError: false,
		},
		{
			name:        "InvalidBackend",
			backend:     "invalid",
			keyType:     "signing",
			algo:        "rsa",
			keyname:     "my-key",
			expectError: true,
		},
		{
			name:        "InvalidKeyType",
			backend:     "software",
			keyType:     "invalid",
			algo:        "rsa",
			keyname:     "my-key",
			expectError: true,
		},
		{
			name:        "InvalidAlgorithm",
			backend:     "software",
			keyType:     "signing",
			algo:        "invalid",
			keyname:     "my-key",
			expectError: true,
		},
		{
			name:        "EmptyKeyname",
			backend:     "software",
			keyType:     "signing",
			algo:        "rsa",
			keyname:     "",
			expectError: true,
		},
		{
			name:        "KeynameWithSlash",
			backend:     "software",
			keyType:     "signing",
			algo:        "rsa",
			keyname:     "my/key",
			expectError: true,
		},
		{
			name:        "KeynameWithDotDot",
			backend:     "software",
			keyType:     "signing",
			algo:        "rsa",
			keyname:     "../key",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyID, err := keychain.NewKeyID(tt.backend, tt.keyType, tt.algo, tt.keyname)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if keyID == "" {
					t.Error("Expected non-empty Key ID")
				}
			}
		})
	}
}

// TestKeyID_ValidateKeyID tests Key ID validation
func TestKeyID_ValidateKeyID(t *testing.T) {
	tests := []struct {
		name        string
		keyID       string
		expectError bool
	}{
		{
			name:        "ValidRSA",
			keyID:       "software:signing:rsa:my-key",
			expectError: false,
		},
		{
			name:        "ValidECDSA",
			keyID:       "software:signing:ecdsa-p256:my-key",
			expectError: false,
		},
		{
			name:        "ValidAES",
			keyID:       "software:secret:aes256-gcm:my-aes-key",
			expectError: false,
		},
		{
			name:        "MissingComponent",
			keyID:       "software:signing:rsa",
			expectError: true,
		},
		{
			name:        "TooManyComponents",
			keyID:       "software:signing:rsa:my-key:extra",
			expectError: true,
		},
		{
			name:        "InvalidBackend",
			keyID:       "invalid:signing:rsa:my-key",
			expectError: true,
		},
		{
			name:        "EmptyString",
			keyID:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := keychain.ValidateKeyID(tt.keyID)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestKeyID_BackendMismatch tests that Key IDs with wrong backend are rejected
func TestKeyID_BackendMismatch(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	// Generate a key
	attrs := &types.KeyAttributes{
		CN:           "test-backend-mismatch",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreSoftware,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	_, err := ks.GenerateRSA(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Try to retrieve with wrong backend in Key ID
	wrongBackends := []string{
		"pkcs11:signing:rsa:test-backend-mismatch",
		"tpm2:signing:rsa:test-backend-mismatch",
		"awskms:signing:rsa:test-backend-mismatch",
	}

	for _, keyID := range wrongBackends {
		_, err := ks.GetKeyByID(keyID)
		if err == nil {
			t.Errorf("Expected error for wrong backend Key ID: %s", keyID)
		}
	}
}

// TestKeyID_AllKeyTypes tests all supported key types
func TestKeyID_AllKeyTypes(t *testing.T) {
	keyTypes := []string{
		"attestation", "ca", "encryption", "endorsement",
		"hmac", "idevid", "secret", "signing", "storage", "tls", "tpm",
	}

	for _, keyType := range keyTypes {
		t.Run(keyType, func(t *testing.T) {
			keyID, err := keychain.NewKeyID("software", keyType, "rsa", "test-key")
			if err != nil {
				t.Errorf("Failed to create Key ID for key type %s: %v", keyType, err)
			}

			err = keychain.ValidateKeyID(string(keyID))
			if err != nil {
				t.Errorf("Key ID validation failed for %s: %v", keyType, err)
			}
		})
	}
}

// TestKeyID_AllAlgorithms tests all supported algorithms
func TestKeyID_AllAlgorithms(t *testing.T) {
	algorithms := []string{
		"rsa", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521", "ed25519",
		"aes128-gcm", "aes192-gcm", "aes256-gcm",
	}

	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			keyID, err := keychain.NewKeyID("software", "signing", algo, "test-key")
			if err != nil {
				t.Errorf("Failed to create Key ID for algorithm %s: %v", algo, err)
			}

			err = keychain.ValidateKeyID(string(keyID))
			if err != nil {
				t.Errorf("Key ID validation failed for %s: %v", algo, err)
			}
		})
	}
}

// TestKeyID_AllBackends tests all supported backends
func TestKeyID_AllBackends(t *testing.T) {
	backends := []string{
		"pkcs8", "symmetric", "software", "pkcs11", "tpm2",
		"awskms", "gcpkms", "azurekv", "vault",
	}

	for _, backend := range backends {
		t.Run(backend, func(t *testing.T) {
			keyID, err := keychain.NewKeyID(backend, "signing", "rsa", "test-key")
			if err != nil {
				t.Errorf("Failed to create Key ID for backend %s: %v", backend, err)
			}

			err = keychain.ValidateKeyID(string(keyID))
			if err != nil {
				t.Errorf("Key ID validation failed for %s: %v", backend, err)
			}
		})
	}
}

// TestKeyID_GetKeyByID_AllAlgorithms tests retrieving keys by ID for all algorithms
func TestKeyID_GetKeyByID_AllAlgorithms(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	tests := []struct {
		name      string
		setupFunc func() (*types.KeyAttributes, error)
		keyID     string
	}{
		{
			name: "RSA",
			setupFunc: func() (*types.KeyAttributes, error) {
				attrs := &types.KeyAttributes{
					CN:           "test-rsa-keyid",
					KeyType:      types.KeyTypeSigning,
					StoreType:    types.StoreSoftware,
					KeyAlgorithm: x509.RSA,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 2048,
					},
					Hash: crypto.SHA256,
				}
				_, err := ks.GenerateRSA(attrs)
				return attrs, err
			},
			keyID: "software:signing:rsa:test-rsa-keyid",
		},
		{
			name: "ECDSA-P256",
			setupFunc: func() (*types.KeyAttributes, error) {
				attrs := &types.KeyAttributes{
					CN:           "test-ecdsa-p256-keyid",
					KeyType:      types.KeyTypeSigning,
					StoreType:    types.StoreSoftware,
					KeyAlgorithm: x509.ECDSA,
					ECCAttributes: &types.ECCAttributes{
						Curve: elliptic.P256(),
					},
					Hash: crypto.SHA256,
				}
				_, err := ks.GenerateECDSA(attrs)
				return attrs, err
			},
			keyID: "software:signing:ecdsa-p256:test-ecdsa-p256-keyid",
		},
		{
			name: "ECDSA-P384",
			setupFunc: func() (*types.KeyAttributes, error) {
				attrs := &types.KeyAttributes{
					CN:           "test-ecdsa-p384-keyid",
					KeyType:      types.KeyTypeSigning,
					StoreType:    types.StoreSoftware,
					KeyAlgorithm: x509.ECDSA,
					ECCAttributes: &types.ECCAttributes{
						Curve: elliptic.P384(),
					},
					Hash: crypto.SHA256,
				}
				_, err := ks.GenerateECDSA(attrs)
				return attrs, err
			},
			keyID: "software:signing:ecdsa-p384:test-ecdsa-p384-keyid",
		},
		{
			name: "Ed25519",
			setupFunc: func() (*types.KeyAttributes, error) {
				attrs := &types.KeyAttributes{
					CN:           "test-ed25519-keyid",
					KeyType:      types.KeyTypeSigning,
					StoreType:    types.StoreSoftware,
					KeyAlgorithm: x509.Ed25519,
				}
				_, err := ks.GenerateEd25519(attrs)
				return attrs, err
			},
			keyID: "software:signing:ed25519:test-ed25519-keyid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup key
			attrs, err := tt.setupFunc()
			if err != nil {
				t.Fatalf("Failed to setup key: %v", err)
			}

			// Retrieve by Key ID
			key, err := ks.GetKeyByID(tt.keyID)
			if err != nil {
				t.Fatalf("Failed to get key by ID: %v", err)
			}

			if key == nil {
				t.Fatal("Retrieved key is nil")
			}

			// Verify it matches the original
			originalKey, err := ks.GetKey(attrs)
			if err != nil {
				t.Fatalf("Failed to get original key: %v", err)
			}

			if originalKey == nil {
				t.Fatal("Original key is nil")
			}

			// Both should be signers
			_, ok1 := key.(crypto.Signer)
			_, ok2 := originalKey.(crypto.Signer)

			if !ok1 || !ok2 {
				t.Error("Keys should both implement crypto.Signer")
			}
		})
	}
}

// TestKeyID_InvalidFormats tests various invalid Key ID formats
func TestKeyID_InvalidFormats(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	invalidKeyIDs := []string{
		"",                                  // Empty
		"software",                          // Missing components
		"software:signing",                  // Missing components
		"software:signing:rsa",              // Missing keyname
		":",                                 // Only separator
		":::",                               // Only separators
		"software:signing:rsa:key:extra",    // Too many components
		"invalid:signing:rsa:key",           // Invalid backend
		"software:invalid:rsa:key",          // Invalid key type
		"software:signing:invalid:key",      // Invalid algorithm
		"software:signing:rsa:/etc/passwd",  // Path traversal
		"software:signing:rsa:../key",       // Path traversal
		"software:signing:rsa:key/../other", // Path traversal
	}

	for _, keyID := range invalidKeyIDs {
		t.Run(keyID, func(t *testing.T) {
			_, err := ks.GetKeyByID(keyID)
			if err == nil {
				t.Errorf("Expected error for invalid Key ID: %s", keyID)
			}
		})
	}
}
