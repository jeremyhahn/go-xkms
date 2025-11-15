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

package keychain_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	backmocks "github.com/jeremyhahn/go-keychain/pkg/backend/mocks"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetKeyByID tests retrieving keys by their unified Key ID.
func TestGetKeyByID(t *testing.T) {
	tests := []struct {
		name        string
		keyID       string
		setupMock   func(*backmocks.MockBackend)
		expectError bool
		errorType   error
	}{
		{
			name:  "valid pkcs8 RSA signing key retrieval",
			keyID: "pkcs8:signing:rsa:test-rsa-key",
			setupMock: func(mb *backmocks.MockBackend) {
				// Generate a real RSA key for testing
				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				mb.GetKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
					if attrs.CN == "test-rsa-key" {
						return rsaKey, nil
					}
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: false,
		},
		{
			name:  "valid pkcs8 ECDSA P-256 signing key retrieval",
			keyID: "pkcs8:signing:ecdsa-p256:test-ecdsa-key",
			setupMock: func(mb *backmocks.MockBackend) {
				// Generate a real ECDSA key for testing
				ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				mb.GetKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
					if attrs.CN == "test-ecdsa-key" {
						return ecKey, nil
					}
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: false,
		},
		{
			name:  "key not found",
			keyID: "pkcs8:signing:rsa:nonexistent-key",
			setupMock: func(mb *backmocks.MockBackend) {
				mb.GetKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: true,
			errorType:   keychain.ErrKeyNotFound,
		},
		{
			name:        "invalid key ID format - only 2 fields",
			keyID:       "pkcs8:test-key",
			setupMock:   func(mb *backmocks.MockBackend) {},
			expectError: true,
			errorType:   keychain.ErrInvalidKeyIDFormat,
		},
		{
			name:        "invalid key ID format - only 3 fields",
			keyID:       "pkcs8:signing:test-key",
			setupMock:   func(mb *backmocks.MockBackend) {},
			expectError: true,
			errorType:   keychain.ErrInvalidKeyIDFormat,
		},
		{
			name:        "invalid backend type",
			keyID:       "unknown:signing:rsa:test-key",
			setupMock:   func(mb *backmocks.MockBackend) {},
			expectError: true,
			errorType:   keychain.ErrInvalidBackendType,
		},
		{
			name:  "backend mismatch",
			keyID: "pkcs11:signing:rsa:test-key", // Request pkcs11, but backend is PKCS8
			setupMock: func(mb *backmocks.MockBackend) {
				// Backend is PKCS8, but Key ID specifies pkcs11
			},
			expectError: true,
			errorType:   keychain.ErrBackendMismatch,
		},
		{
			name:        "invalid key type",
			keyID:       "pkcs8:invalid-type:rsa:test-key",
			setupMock:   func(mb *backmocks.MockBackend) {},
			expectError: true,
		},
		{
			name:        "invalid algorithm",
			keyID:       "pkcs8:signing:invalid-algo:test-key",
			setupMock:   func(mb *backmocks.MockBackend) {},
			expectError: true,
		},
		{
			name:        "invalid ECDSA curve",
			keyID:       "pkcs8:signing:ecdsa-invalid:test-key",
			setupMock:   func(mb *backmocks.MockBackend) {},
			expectError: true,
		},
		{
			name:  "valid pkcs8 ECDSA P-384 signing key retrieval",
			keyID: "pkcs8:signing:ecdsa-p384:test-ecdsa-p384-key",
			setupMock: func(mb *backmocks.MockBackend) {
				// Generate a real ECDSA P-384 key for testing
				ecKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				mb.GetKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
					if attrs.CN == "test-ecdsa-p384-key" {
						return ecKey, nil
					}
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: false,
		},
		{
			name:  "valid pkcs8 ECDSA P-521 signing key retrieval",
			keyID: "pkcs8:signing:ecdsa-p521:test-ecdsa-p521-key",
			setupMock: func(mb *backmocks.MockBackend) {
				// Generate a real ECDSA P-521 key for testing
				ecKey, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				mb.GetKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
					if attrs.CN == "test-ecdsa-p521-key" {
						return ecKey, nil
					}
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: false,
		},
		{
			name:  "valid pkcs8 secret AES-128-GCM key retrieval",
			keyID: "pkcs8:secret:aes128-gcm:test-aes-key",
			setupMock: func(mb *backmocks.MockBackend) {
				// Return a mock symmetric key (byte slice)
				mb.GetKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
					if attrs.CN == "test-aes-key" {
						return []byte("0123456789abcdef"), nil // 16 bytes for AES-128
					}
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: false,
		},
		{
			name:  "valid pkcs8 secret AES-192-GCM key retrieval",
			keyID: "pkcs8:secret:aes192-gcm:test-aes-192-key",
			setupMock: func(mb *backmocks.MockBackend) {
				// Return a mock symmetric key (byte slice)
				mb.GetKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
					if attrs.CN == "test-aes-192-key" {
						return []byte("0123456789abcdef01234567"), nil // 24 bytes for AES-192
					}
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: false,
		},
		{
			name:  "valid pkcs8 secret AES-256-GCM key retrieval",
			keyID: "pkcs8:secret:aes256-gcm:test-aes-256-key",
			setupMock: func(mb *backmocks.MockBackend) {
				// Return a mock symmetric key (byte slice)
				mb.GetKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
					if attrs.CN == "test-aes-256-key" {
						return []byte("0123456789abcdef0123456789abcdef"), nil // 32 bytes for AES-256
					}
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks, mockBackend, _ := setupKeyStore()
			defer ks.Close()

			// Setup mock behavior
			tt.setupMock(mockBackend)

			// Test GetKeyByID
			key, err := ks.GetKeyByID(tt.keyID)

			if tt.expectError {
				require.Error(t, err, "Expected error for test case: %s", tt.name)
				if tt.errorType != nil {
					assert.ErrorIs(t, err, tt.errorType, "Expected specific error type")
				}
				assert.Nil(t, key, "Key should be nil on error")
				return
			}

			require.NoError(t, err, "Unexpected error: %v", err)
			assert.NotNil(t, key, "Key should not be nil")
		})
	}
}

// TestGetSignerByID tests retrieving signers by their unified Key ID.
func TestGetSignerByID(t *testing.T) {
	tests := []struct {
		name        string
		keyID       string
		setupMock   func(*backmocks.MockBackend)
		expectError bool
		errorType   error
	}{
		{
			name:  "valid RSA signer retrieval",
			keyID: "pkcs8:signing:rsa:test-signing-key",
			setupMock: func(mb *backmocks.MockBackend) {
				// Generate a real RSA key for testing
				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				mb.SignerFunc = func(attrs *types.KeyAttributes) (crypto.Signer, error) {
					if attrs.CN == "test-signing-key" {
						return rsaKey, nil
					}
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: false,
		},
		{
			name:  "signer not found",
			keyID: "pkcs8:signing:rsa:nonexistent-signer",
			setupMock: func(mb *backmocks.MockBackend) {
				mb.SignerFunc = func(attrs *types.KeyAttributes) (crypto.Signer, error) {
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: true,
			errorType:   keychain.ErrKeyNotFound,
		},
		{
			name:        "invalid key ID format - only 1 field",
			keyID:       "invalid",
			setupMock:   func(mb *backmocks.MockBackend) {},
			expectError: true,
			errorType:   keychain.ErrInvalidKeyIDFormat,
		},
		{
			name:        "invalid key ID format - only 2 fields",
			keyID:       "pkcs8:test-key",
			setupMock:   func(mb *backmocks.MockBackend) {},
			expectError: true,
			errorType:   keychain.ErrInvalidKeyIDFormat,
		},
		{
			name:  "backend mismatch",
			keyID: "tpm2:signing:rsa:test-key",
			setupMock: func(mb *backmocks.MockBackend) {
				// Backend is PKCS8, but Key ID specifies tpm2
			},
			expectError: true,
			errorType:   keychain.ErrBackendMismatch,
		},
		{
			name:  "valid ECDSA P-256 signer retrieval",
			keyID: "pkcs8:signing:ecdsa-p256:test-ecdsa-signer",
			setupMock: func(mb *backmocks.MockBackend) {
				ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				mb.SignerFunc = func(attrs *types.KeyAttributes) (crypto.Signer, error) {
					if attrs.CN == "test-ecdsa-signer" {
						return ecKey, nil
					}
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: false,
		},
		{
			name:  "valid ECDSA P-384 signer retrieval",
			keyID: "pkcs8:signing:ecdsa-p384:test-ecdsa-p384-signer",
			setupMock: func(mb *backmocks.MockBackend) {
				ecKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				mb.SignerFunc = func(attrs *types.KeyAttributes) (crypto.Signer, error) {
					if attrs.CN == "test-ecdsa-p384-signer" {
						return ecKey, nil
					}
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: false,
		},
		{
			name:  "valid ECDSA P-521 signer retrieval",
			keyID: "pkcs8:signing:ecdsa-p521:test-ecdsa-p521-signer",
			setupMock: func(mb *backmocks.MockBackend) {
				ecKey, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				mb.SignerFunc = func(attrs *types.KeyAttributes) (crypto.Signer, error) {
					if attrs.CN == "test-ecdsa-p521-signer" {
						return ecKey, nil
					}
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: false,
		},
		{
			name:  "valid AES-128-GCM signer retrieval",
			keyID: "pkcs8:secret:aes128-gcm:test-aes128-signer",
			setupMock: func(mb *backmocks.MockBackend) {
				// Mock signer that returns a signer (not typical but tests the code path)
				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				mb.SignerFunc = func(attrs *types.KeyAttributes) (crypto.Signer, error) {
					if attrs.CN == "test-aes128-signer" {
						return rsaKey, nil
					}
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: false,
		},
		{
			name:  "valid AES-192-GCM signer retrieval",
			keyID: "pkcs8:secret:aes192-gcm:test-aes192-signer",
			setupMock: func(mb *backmocks.MockBackend) {
				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				mb.SignerFunc = func(attrs *types.KeyAttributes) (crypto.Signer, error) {
					if attrs.CN == "test-aes192-signer" {
						return rsaKey, nil
					}
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: false,
		},
		{
			name:  "valid AES-256-GCM signer retrieval",
			keyID: "pkcs8:secret:aes256-gcm:test-aes256-signer",
			setupMock: func(mb *backmocks.MockBackend) {
				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				mb.SignerFunc = func(attrs *types.KeyAttributes) (crypto.Signer, error) {
					if attrs.CN == "test-aes256-signer" {
						return rsaKey, nil
					}
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: false,
		},
		{
			name:        "invalid key type for signer",
			keyID:       "pkcs8:invalid:rsa:test-key",
			setupMock:   func(mb *backmocks.MockBackend) {},
			expectError: true,
		},
		{
			name:        "invalid algorithm for signer",
			keyID:       "pkcs8:signing:invalid-algo:test-key",
			setupMock:   func(mb *backmocks.MockBackend) {},
			expectError: true,
		},
		{
			name:        "invalid ECDSA curve for signer",
			keyID:       "pkcs8:signing:ecdsa-p999:test-key",
			setupMock:   func(mb *backmocks.MockBackend) {},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks, mockBackend, _ := setupKeyStore()
			defer ks.Close()

			// Setup mock behavior
			tt.setupMock(mockBackend)

			// Test GetSignerByID
			signer, err := ks.GetSignerByID(tt.keyID)

			if tt.expectError {
				require.Error(t, err, "Expected error for test case: %s", tt.name)
				if tt.errorType != nil {
					assert.ErrorIs(t, err, tt.errorType, "Expected specific error type")
				}
				assert.Nil(t, signer, "Signer should be nil on error")
				return
			}

			require.NoError(t, err, "Unexpected error: %v", err)
			assert.NotNil(t, signer, "Signer should not be nil")

			// Verify it implements crypto.Signer
			_, ok := signer.(crypto.Signer)
			assert.True(t, ok, "Result should implement crypto.Signer")
		})
	}
}

// TestGetDecrypterByID tests retrieving decrypters by their unified Key ID.
func TestGetDecrypterByID(t *testing.T) {
	tests := []struct {
		name        string
		keyID       string
		setupMock   func(*backmocks.MockBackend)
		expectError bool
		errorType   error
	}{
		{
			name:  "valid RSA decrypter retrieval",
			keyID: "pkcs8:encryption:rsa:test-rsa-key",
			setupMock: func(mb *backmocks.MockBackend) {
				// Generate a real RSA key for testing
				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				mb.DecrypterFunc = func(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
					if attrs.CN == "test-rsa-key" {
						return rsaKey, nil
					}
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: false,
		},
		{
			name:  "decrypter not found",
			keyID: "pkcs8:encryption:rsa:nonexistent-key",
			setupMock: func(mb *backmocks.MockBackend) {
				mb.DecrypterFunc = func(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: true,
			errorType:   keychain.ErrKeyNotFound,
		},
		{
			name:        "invalid key ID format - no colons",
			keyID:       "no-colon",
			setupMock:   func(mb *backmocks.MockBackend) {},
			expectError: true,
			errorType:   keychain.ErrInvalidKeyIDFormat,
		},
		{
			name:        "invalid key ID format - only 2 fields",
			keyID:       "pkcs8:encryption-key",
			setupMock:   func(mb *backmocks.MockBackend) {},
			expectError: true,
			errorType:   keychain.ErrInvalidKeyIDFormat,
		},
		{
			name:  "backend mismatch",
			keyID: "awskms:encryption:rsa:encryption-key",
			setupMock: func(mb *backmocks.MockBackend) {
				// Backend is PKCS8, but Key ID specifies awskms
			},
			expectError: true,
			errorType:   keychain.ErrBackendMismatch,
		},
		{
			name:  "valid ECDSA P-256 decrypter retrieval",
			keyID: "pkcs8:encryption:ecdsa-p256:test-ecdsa-decrypter",
			setupMock: func(mb *backmocks.MockBackend) {
				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				mb.DecrypterFunc = func(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
					if attrs.CN == "test-ecdsa-decrypter" {
						return rsaKey, nil
					}
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: false,
		},
		{
			name:  "valid ECDSA P-384 decrypter retrieval",
			keyID: "pkcs8:encryption:ecdsa-p384:test-ecdsa-p384-decrypter",
			setupMock: func(mb *backmocks.MockBackend) {
				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				mb.DecrypterFunc = func(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
					if attrs.CN == "test-ecdsa-p384-decrypter" {
						return rsaKey, nil
					}
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: false,
		},
		{
			name:  "valid ECDSA P-521 decrypter retrieval",
			keyID: "pkcs8:encryption:ecdsa-p521:test-ecdsa-p521-decrypter",
			setupMock: func(mb *backmocks.MockBackend) {
				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				mb.DecrypterFunc = func(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
					if attrs.CN == "test-ecdsa-p521-decrypter" {
						return rsaKey, nil
					}
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: false,
		},
		{
			name:  "valid AES-128-GCM decrypter retrieval",
			keyID: "pkcs8:secret:aes128-gcm:test-aes128-decrypter",
			setupMock: func(mb *backmocks.MockBackend) {
				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				mb.DecrypterFunc = func(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
					if attrs.CN == "test-aes128-decrypter" {
						return rsaKey, nil
					}
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: false,
		},
		{
			name:  "valid AES-192-GCM decrypter retrieval",
			keyID: "pkcs8:secret:aes192-gcm:test-aes192-decrypter",
			setupMock: func(mb *backmocks.MockBackend) {
				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				mb.DecrypterFunc = func(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
					if attrs.CN == "test-aes192-decrypter" {
						return rsaKey, nil
					}
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: false,
		},
		{
			name:  "valid AES-256-GCM decrypter retrieval",
			keyID: "pkcs8:secret:aes256-gcm:test-aes256-decrypter",
			setupMock: func(mb *backmocks.MockBackend) {
				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				mb.DecrypterFunc = func(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
					if attrs.CN == "test-aes256-decrypter" {
						return rsaKey, nil
					}
					return nil, keychain.ErrKeyNotFound
				}
			},
			expectError: false,
		},
		{
			name:        "invalid key type for decrypter",
			keyID:       "pkcs8:invalid:rsa:test-key",
			setupMock:   func(mb *backmocks.MockBackend) {},
			expectError: true,
		},
		{
			name:        "invalid algorithm for decrypter",
			keyID:       "pkcs8:encryption:invalid-algo:test-key",
			setupMock:   func(mb *backmocks.MockBackend) {},
			expectError: true,
		},
		{
			name:        "invalid ECDSA curve for decrypter",
			keyID:       "pkcs8:encryption:ecdsa-p111:test-key",
			setupMock:   func(mb *backmocks.MockBackend) {},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks, mockBackend, _ := setupKeyStore()
			defer ks.Close()

			// Setup mock behavior
			tt.setupMock(mockBackend)

			// Test GetDecrypterByID
			decrypter, err := ks.GetDecrypterByID(tt.keyID)

			if tt.expectError {
				require.Error(t, err, "Expected error for test case: %s", tt.name)
				if tt.errorType != nil {
					assert.ErrorIs(t, err, tt.errorType, "Expected specific error type")
				}
				assert.Nil(t, decrypter, "Decrypter should be nil on error")
				return
			}

			require.NoError(t, err, "Unexpected error: %v", err)
			assert.NotNil(t, decrypter, "Decrypter should not be nil")

			// Verify it implements crypto.Decrypter
			_, ok := decrypter.(crypto.Decrypter)
			assert.True(t, ok, "Result should implement crypto.Decrypter")
		})
	}
}

// TestKeyID_IntegrationFlow tests the complete flow of using Key IDs.
func TestKeyID_IntegrationFlow(t *testing.T) {
	ks, mockBackend, _ := setupKeyStore()
	defer ks.Close()

	// Generate a real RSA key for testing
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Setup mock to return our key
	mockBackend.GetKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
		if attrs.CN == "integration-test-key" {
			return rsaKey, nil
		}
		return nil, keychain.ErrKeyNotFound
	}

	mockBackend.SignerFunc = func(attrs *types.KeyAttributes) (crypto.Signer, error) {
		if attrs.CN == "integration-test-key" {
			return rsaKey, nil
		}
		return nil, keychain.ErrKeyNotFound
	}

	mockBackend.DecrypterFunc = func(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
		if attrs.CN == "integration-test-key" {
			return rsaKey, nil
		}
		return nil, keychain.ErrKeyNotFound
	}

	keyID := "pkcs8:signing:rsa:integration-test-key"

	// Test GetKeyByID
	key, err := ks.GetKeyByID(keyID)
	require.NoError(t, err)
	assert.NotNil(t, key)

	// Test GetSignerByID
	signer, err := ks.GetSignerByID(keyID)
	require.NoError(t, err)
	assert.NotNil(t, signer)

	// Verify signing works
	digest := make([]byte, 32)
	_, err = rand.Read(digest)
	require.NoError(t, err)

	signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)

	// Test GetDecrypterByID with encryption key ID
	encryptKeyID := "pkcs8:encryption:rsa:integration-test-key"
	decrypter, err := ks.GetDecrypterByID(encryptKeyID)
	require.NoError(t, err)
	assert.NotNil(t, decrypter)
}
