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

//go:build gcpkms

package gcpkms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// TestDecrypter tests getting a Decrypter interface from the GCP KMS backend.
func TestDecrypter(t *testing.T) {
	// Generate a test RSA key pair for mocking
	testRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate test RSA key")

	testPublicKeyBytes, err := x509.MarshalPKIXPublicKey(&testRSAKey.PublicKey)
	require.NoError(t, err, "Failed to marshal public key")

	testPublicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: testPublicKeyBytes,
	})

	tests := []struct {
		name        string
		attrs       *types.KeyAttributes
		setupMock   func(*MockKMSClient)
		wantErr     bool
		expectedErr error
	}{
		{
			name: "get decrypter for RSA-2048 OAEP encryption key",
			attrs: &types.KeyAttributes{
				CN:           "test-decrypter",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_ENCRYPTION,
				StoreType:    backend.STORE_GCPKMS,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			},
			setupMock: func(m *MockKMSClient) {
				m.GetPublicKeyFunc = func(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error) {
					return &kmspb.PublicKey{
						Pem:       string(testPublicKeyPEM),
						Algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name: "get decrypter for RSA-3072 OAEP encryption key",
			attrs: &types.KeyAttributes{
				CN:           "test-decrypter-3072",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_ENCRYPTION,
				StoreType:    backend.STORE_GCPKMS,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 3072,
				},
			},
			setupMock: func(m *MockKMSClient) {
				m.GetPublicKeyFunc = func(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error) {
					return &kmspb.PublicKey{
						Pem:       string(testPublicKeyPEM),
						Algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256,
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name: "get decrypter for RSA-4096 OAEP encryption key",
			attrs: &types.KeyAttributes{
				CN:           "test-decrypter-4096",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_ENCRYPTION,
				StoreType:    backend.STORE_GCPKMS,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 4096,
				},
			},
			setupMock: func(m *MockKMSClient) {
				m.GetPublicKeyFunc = func(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error) {
					return &kmspb.PublicKey{
						Pem:       string(testPublicKeyPEM),
						Algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256,
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name:  "error with nil attributes",
			attrs: nil,
			setupMock: func(m *MockKMSClient) {
				// No setup needed, should fail before calling mock
			},
			wantErr:     true,
			expectedErr: nil, // Just check for any error
		},
		{
			name: "error with signing key (not decryption key)",
			attrs: &types.KeyAttributes{
				CN:           "test-signing-key",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_GCPKMS,
			},
			setupMock: func(m *MockKMSClient) {
				m.GetPublicKeyFunc = func(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error) {
					return &kmspb.PublicKey{
						Pem:       string(testPublicKeyPEM),
						Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256, // Signing algorithm, not decrypt
					}, nil
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockKMSClient{}
			tt.setupMock(mockClient)

			config := &Config{
				ProjectID:   "test-project",
				LocationID:  "us-central1",
				KeyRingID:   "test-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			}
			b, err := NewBackendWithClient(config, mockClient)
			require.NoError(t, err, "Failed to create backend")

			decrypter, err := b.Decrypter(tt.attrs)
			if tt.wantErr {
				assert.Error(t, err, "Expected error but got none")
				if tt.expectedErr != nil {
					assert.ErrorIs(t, err, tt.expectedErr, "Expected specific error")
				}
				return
			}

			require.NoError(t, err, "Failed to get Decrypter")
			require.NotNil(t, decrypter, "Decrypter should not be nil")

			// Verify Public() returns the correct public key
			pubKey := decrypter.Public()
			require.NotNil(t, pubKey, "Public key should not be nil")

			_, ok := pubKey.(*rsa.PublicKey)
			require.True(t, ok, "Public key should be an RSA public key")
		})
	}
}

// TestRSADecrypt_OAEP tests RSA-OAEP decryption with GCP KMS.
// GCP KMS supports OAEP with SHA256, SHA1 hash algorithms.
func TestRSADecrypt_OAEP(t *testing.T) {
	// Generate a test RSA key pair for mocking
	testRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate test RSA key")

	testPublicKeyBytes, err := x509.MarshalPKIXPublicKey(&testRSAKey.PublicKey)
	require.NoError(t, err, "Failed to marshal public key")

	testPublicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: testPublicKeyBytes,
	})

	tests := []struct {
		name      string
		attrs     *types.KeyAttributes
		plaintext []byte
		algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
		setupMock func(*MockKMSClient, []byte)
		wantErr   bool
	}{
		{
			name: "decrypt RSA-2048 OAEP SHA256",
			attrs: &types.KeyAttributes{
				CN:           "test-oaep-2048",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_ENCRYPTION,
				StoreType:    backend.STORE_GCPKMS,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			},
			plaintext: []byte("test message for RSA-2048 OAEP SHA256"),
			algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
			setupMock: func(m *MockKMSClient, plaintext []byte) {
				m.GetPublicKeyFunc = func(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error) {
					return &kmspb.PublicKey{
						Pem:       string(testPublicKeyPEM),
						Algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
					}, nil
				}
				m.AsymmetricDecryptFunc = func(ctx context.Context, req *kmspb.AsymmetricDecryptRequest, opts ...interface{}) (*kmspb.AsymmetricDecryptResponse, error) {
					return &kmspb.AsymmetricDecryptResponse{
						Plaintext: plaintext,
						PlaintextCrc32C: &wrapperspb.Int64Value{
							Value: int64(crc32c(plaintext)),
						},
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name: "decrypt RSA-3072 OAEP SHA256",
			attrs: &types.KeyAttributes{
				CN:           "test-oaep-3072",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_ENCRYPTION,
				StoreType:    backend.STORE_GCPKMS,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 3072,
				},
			},
			plaintext: []byte("test message for RSA-3072 OAEP SHA256"),
			algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256,
			setupMock: func(m *MockKMSClient, plaintext []byte) {
				m.GetPublicKeyFunc = func(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error) {
					return &kmspb.PublicKey{
						Pem:       string(testPublicKeyPEM),
						Algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256,
					}, nil
				}
				m.AsymmetricDecryptFunc = func(ctx context.Context, req *kmspb.AsymmetricDecryptRequest, opts ...interface{}) (*kmspb.AsymmetricDecryptResponse, error) {
					return &kmspb.AsymmetricDecryptResponse{
						Plaintext: plaintext,
						PlaintextCrc32C: &wrapperspb.Int64Value{
							Value: int64(crc32c(plaintext)),
						},
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name: "decrypt RSA-4096 OAEP SHA256",
			attrs: &types.KeyAttributes{
				CN:           "test-oaep-4096",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_ENCRYPTION,
				StoreType:    backend.STORE_GCPKMS,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 4096,
				},
			},
			plaintext: []byte("test message for RSA-4096 OAEP SHA256"),
			algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256,
			setupMock: func(m *MockKMSClient, plaintext []byte) {
				m.GetPublicKeyFunc = func(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error) {
					return &kmspb.PublicKey{
						Pem:       string(testPublicKeyPEM),
						Algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256,
					}, nil
				}
				m.AsymmetricDecryptFunc = func(ctx context.Context, req *kmspb.AsymmetricDecryptRequest, opts ...interface{}) (*kmspb.AsymmetricDecryptResponse, error) {
					return &kmspb.AsymmetricDecryptResponse{
						Plaintext: plaintext,
						PlaintextCrc32C: &wrapperspb.Int64Value{
							Value: int64(crc32c(plaintext)),
						},
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name: "decrypt RSA-2048 OAEP SHA1",
			attrs: &types.KeyAttributes{
				CN:           "test-oaep-sha1-2048",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_ENCRYPTION,
				StoreType:    backend.STORE_GCPKMS,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			},
			plaintext: []byte("test message for RSA-2048 OAEP SHA1"),
			algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA1,
			setupMock: func(m *MockKMSClient, plaintext []byte) {
				m.GetPublicKeyFunc = func(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error) {
					return &kmspb.PublicKey{
						Pem:       string(testPublicKeyPEM),
						Algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA1,
					}, nil
				}
				m.AsymmetricDecryptFunc = func(ctx context.Context, req *kmspb.AsymmetricDecryptRequest, opts ...interface{}) (*kmspb.AsymmetricDecryptResponse, error) {
					return &kmspb.AsymmetricDecryptResponse{
						Plaintext: plaintext,
						PlaintextCrc32C: &wrapperspb.Int64Value{
							Value: int64(crc32c(plaintext)),
						},
					}, nil
				}
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockKMSClient{}
			tt.setupMock(mockClient, tt.plaintext)

			config := &Config{
				ProjectID:   "test-project",
				LocationID:  "us-central1",
				KeyRingID:   "test-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			}
			b, err := NewBackendWithClient(config, mockClient)
			require.NoError(t, err, "Failed to create backend")

			// Get the decrypter
			decrypter, err := b.Decrypter(tt.attrs)
			require.NoError(t, err, "Failed to get Decrypter")

			// Create test ciphertext (in real scenario, this would be encrypted data)
			ciphertext := []byte("mock ciphertext")

			// Decrypt using crypto.Decrypter interface with OAEP options
			opts := &rsa.OAEPOptions{
				Hash: crypto.SHA256,
			}

			plaintext, err := decrypter.Decrypt(rand.Reader, ciphertext, opts)
			if tt.wantErr {
				assert.Error(t, err, "Expected error but got none")
				return
			}

			require.NoError(t, err, "Decryption failed")
			assert.Equal(t, tt.plaintext, plaintext, "Decrypted plaintext doesn't match")
		})
	}
}

// TestDecrypterRoundTrip tests the complete encrypt/decrypt workflow using crypto.Decrypter.
// This verifies that the Decrypter interface can successfully decrypt ciphertext
// that was encrypted with the public key.
func TestDecrypterRoundTrip(t *testing.T) {
	// Generate a test RSA key pair for round-trip testing
	testRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate test RSA key")

	testPublicKeyBytes, err := x509.MarshalPKIXPublicKey(&testRSAKey.PublicKey)
	require.NoError(t, err, "Failed to marshal public key")

	testPublicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: testPublicKeyBytes,
	})

	tests := []struct {
		name      string
		attrs     *types.KeyAttributes
		plaintext []byte
		oaepOpts  *rsa.OAEPOptions
		algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	}{
		{
			name: "RSA-2048 OAEP SHA256 round trip",
			attrs: &types.KeyAttributes{
				CN:           "test-roundtrip-2048",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_ENCRYPTION,
				StoreType:    backend.STORE_GCPKMS,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			},
			plaintext: []byte("test message for round-trip encryption"),
			oaepOpts: &rsa.OAEPOptions{
				Hash: crypto.SHA256,
			},
			algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
		},
		{
			name: "RSA-3072 OAEP SHA256 round trip",
			attrs: &types.KeyAttributes{
				CN:           "test-roundtrip-3072",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_ENCRYPTION,
				StoreType:    backend.STORE_GCPKMS,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 3072,
				},
			},
			plaintext: []byte("test message for 3072-bit round-trip"),
			oaepOpts: &rsa.OAEPOptions{
				Hash: crypto.SHA256,
			},
			algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockKMSClient{}

			// Setup mock to return the public key
			mockClient.GetPublicKeyFunc = func(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error) {
				return &kmspb.PublicKey{
					Pem:       string(testPublicKeyPEM),
					Algorithm: tt.algorithm,
				}, nil
			}

			// Setup mock to decrypt by actually decrypting with the test private key
			mockClient.AsymmetricDecryptFunc = func(ctx context.Context, req *kmspb.AsymmetricDecryptRequest, opts ...interface{}) (*kmspb.AsymmetricDecryptResponse, error) {
				// In a real scenario, GCP KMS would decrypt using its private key
				// For testing, we decrypt using our test private key
				plaintext, err := rsa.DecryptOAEP(
					tt.oaepOpts.Hash.New(),
					rand.Reader,
					testRSAKey,
					req.Ciphertext,
					nil,
				)
				if err != nil {
					return nil, err
				}
				return &kmspb.AsymmetricDecryptResponse{
					Plaintext: plaintext,
					PlaintextCrc32C: &wrapperspb.Int64Value{
						Value: int64(crc32c(plaintext)),
					},
				}, nil
			}

			config := &Config{
				ProjectID:   "test-project",
				LocationID:  "us-central1",
				KeyRingID:   "test-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			}
			b, err := NewBackendWithClient(config, mockClient)
			require.NoError(t, err, "Failed to create backend")

			// Get the decrypter
			decrypter, err := b.Decrypter(tt.attrs)
			require.NoError(t, err, "Failed to get Decrypter")

			// Get the public key from the decrypter
			pubKey := decrypter.Public()
			require.NotNil(t, pubKey, "Public key should not be nil")

			rsaPubKey, ok := pubKey.(*rsa.PublicKey)
			require.True(t, ok, "Public key should be an RSA public key")

			// Encrypt the plaintext using the public key
			ciphertext, err := rsa.EncryptOAEP(
				tt.oaepOpts.Hash.New(),
				rand.Reader,
				rsaPubKey,
				tt.plaintext,
				nil,
			)
			require.NoError(t, err, "Encryption failed")

			// Decrypt using the Decrypter interface
			decrypted, err := decrypter.Decrypt(rand.Reader, ciphertext, tt.oaepOpts)
			require.NoError(t, err, "Decryption failed")

			// Verify the decrypted plaintext matches the original
			assert.Equal(t, tt.plaintext, decrypted, "Decrypted plaintext doesn't match original")
		})
	}
}

// TestDecrypterWithInvalidChecksum tests that decryption fails when GCP KMS
// returns an invalid CRC32C checksum for the plaintext.
func TestDecrypterWithInvalidChecksum(t *testing.T) {
	testRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate test RSA key")

	testPublicKeyBytes, err := x509.MarshalPKIXPublicKey(&testRSAKey.PublicKey)
	require.NoError(t, err, "Failed to marshal public key")

	testPublicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: testPublicKeyBytes,
	})

	mockClient := &MockKMSClient{}

	mockClient.GetPublicKeyFunc = func(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error) {
		return &kmspb.PublicKey{
			Pem:       string(testPublicKeyPEM),
			Algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
		}, nil
	}

	// Setup mock to return plaintext with INVALID checksum
	plaintext := []byte("test plaintext")
	invalidChecksum := int64(12345) // Wrong checksum
	mockClient.AsymmetricDecryptFunc = func(ctx context.Context, req *kmspb.AsymmetricDecryptRequest, opts ...interface{}) (*kmspb.AsymmetricDecryptResponse, error) {
		return &kmspb.AsymmetricDecryptResponse{
			Plaintext: plaintext,
			PlaintextCrc32C: &wrapperspb.Int64Value{
				Value: invalidChecksum, // Intentionally wrong checksum
			},
		}, nil
	}

	config := &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  memory.New(),
		CertStorage: memory.New(),
	}
	b, err := NewBackendWithClient(config, mockClient)
	require.NoError(t, err, "Failed to create backend")

	attrs := &types.KeyAttributes{
		CN:           "test-checksum",
		KeyAlgorithm: x509.RSA,
		KeyType:      backend.KEY_TYPE_ENCRYPTION,
		StoreType:    backend.STORE_GCPKMS,
	}

	decrypter, err := b.Decrypter(attrs)
	require.NoError(t, err, "Failed to get Decrypter")

	ciphertext := []byte("mock ciphertext")
	opts := &rsa.OAEPOptions{
		Hash: crypto.SHA256,
	}

	// Decryption should fail due to checksum mismatch
	_, err = decrypter.Decrypt(rand.Reader, ciphertext, opts)
	assert.Error(t, err, "Expected checksum mismatch error")
	assert.Contains(t, err.Error(), "checksum", "Error should mention checksum")
}
