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

//go:build awskms

package awskms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDecrypter tests getting a Decrypter interface from the backend.
func TestDecrypter(t *testing.T) {
	// Generate a test RSA key pair for mocking
	testRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate test RSA key")

	testPublicKeyBytes, err := x509.MarshalPKIXPublicKey(&testRSAKey.PublicKey)
	require.NoError(t, err, "Failed to marshal public key")

	tests := []struct {
		name        string
		attrs       *types.KeyAttributes
		setupMock   func(*MockKMSClient)
		wantErr     bool
		expectedErr error
	}{
		{
			name: "get decrypter for RSA-2048 encryption key",
			attrs: &types.KeyAttributes{
				CN:           "test-decrypter",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_ENCRYPTION,
				StoreType:    backend.STORE_AWSKMS,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			},
			setupMock: func(m *MockKMSClient) {
				m.GetPublicKeyFunc = func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
					keySpec := kmstypes.KeySpecRsa2048
					keyUsage := kmstypes.KeyUsageTypeEncryptDecrypt
					return &kms.GetPublicKeyOutput{
						KeyId:     aws.String("test-key-id"),
						KeySpec:   keySpec,
						KeyUsage:  keyUsage,
						PublicKey: testPublicKeyBytes,
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name: "get decrypter for RSA-3072 encryption key",
			attrs: &types.KeyAttributes{
				CN:           "test-decrypter-3072",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_ENCRYPTION,
				StoreType:    backend.STORE_AWSKMS,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 3072,
				},
			},
			setupMock: func(m *MockKMSClient) {
				m.GetPublicKeyFunc = func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
					keySpec := kmstypes.KeySpecRsa3072
					keyUsage := kmstypes.KeyUsageTypeEncryptDecrypt
					return &kms.GetPublicKeyOutput{
						KeyId:     aws.String("test-key-id-3072"),
						KeySpec:   keySpec,
						KeyUsage:  keyUsage,
						PublicKey: testPublicKeyBytes,
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name:        "error with nil attributes",
			attrs:       nil,
			setupMock:   func(m *MockKMSClient) {},
			wantErr:     true,
			expectedErr: nil, // Just check for any error, not specific type
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockKMSClient{}
			tt.setupMock(mockClient)

			config := &Config{
				Region:      "us-east-1",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
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

// TestRSADecrypt_PKCS1v15 tests RSA PKCS#1 v1.5 decryption.
func TestRSADecrypt_PKCS1v15(t *testing.T) {
	// Generate a test RSA key pair for mocking
	testRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate test RSA key")

	testPublicKeyBytes, err := x509.MarshalPKIXPublicKey(&testRSAKey.PublicKey)
	require.NoError(t, err, "Failed to marshal public key")

	tests := []struct {
		name      string
		attrs     *types.KeyAttributes
		plaintext []byte
		setupMock func(*MockKMSClient, []byte)
		wantErr   bool
	}{
		{
			name: "decrypt RSA-2048 PKCS#1 v1.5",
			attrs: &types.KeyAttributes{
				CN:           "test-decrypt-pkcs1",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_ENCRYPTION,
				StoreType:    backend.STORE_AWSKMS,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			},
			plaintext: []byte("Test message for PKCS#1 v1.5 decryption"),
			setupMock: func(m *MockKMSClient, plaintext []byte) {
				m.GetPublicKeyFunc = func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
					keySpec := kmstypes.KeySpecRsa2048
					keyUsage := kmstypes.KeyUsageTypeEncryptDecrypt
					return &kms.GetPublicKeyOutput{
						KeyId:     aws.String("test-key-id"),
						KeySpec:   keySpec,
						KeyUsage:  keyUsage,
						PublicKey: testPublicKeyBytes,
					}, nil
				}

				m.DecryptFunc = func(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
					// Mock decryption - in real AWS, this would actually decrypt
					// For testing, we just return the plaintext
					return &kms.DecryptOutput{
						Plaintext: plaintext,
						KeyId:     aws.String("test-key-id"),
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name: "decrypt RSA-3072 PKCS#1 v1.5",
			attrs: &types.KeyAttributes{
				CN:           "test-decrypt-pkcs1-3072",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_ENCRYPTION,
				StoreType:    backend.STORE_AWSKMS,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 3072,
				},
			},
			plaintext: []byte("Test message for RSA-3072 PKCS#1 v1.5"),
			setupMock: func(m *MockKMSClient, plaintext []byte) {
				m.GetPublicKeyFunc = func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
					keySpec := kmstypes.KeySpecRsa3072
					keyUsage := kmstypes.KeyUsageTypeEncryptDecrypt
					return &kms.GetPublicKeyOutput{
						KeyId:     aws.String("test-key-id-3072"),
						KeySpec:   keySpec,
						KeyUsage:  keyUsage,
						PublicKey: testPublicKeyBytes,
					}, nil
				}

				m.DecryptFunc = func(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
					return &kms.DecryptOutput{
						Plaintext: plaintext,
						KeyId:     aws.String("test-key-id-3072"),
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
				Region:      "us-east-1",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}
			b, err := NewBackendWithClient(config, mockClient)
			require.NoError(t, err, "Failed to create backend")

			// Get decrypter
			decrypter, err := b.Decrypter(tt.attrs)
			require.NoError(t, err, "Failed to get Decrypter")
			require.NotNil(t, decrypter, "Decrypter should not be nil")

			// Encrypt with the public key using PKCS#1 v1.5
			rsaPub, ok := decrypter.Public().(*rsa.PublicKey)
			require.True(t, ok, "Public key should be an RSA public key")

			ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, tt.plaintext)
			require.NoError(t, err, "Failed to encrypt with PKCS#1 v1.5")

			// Decrypt using Decrypter interface with nil opts (PKCS#1 v1.5)
			decrypted, err := decrypter.Decrypt(rand.Reader, ciphertext, nil)

			if tt.wantErr {
				assert.Error(t, err, "Expected error but got none")
				return
			}

			require.NoError(t, err, "Failed to decrypt")
			assert.Equal(t, tt.plaintext, decrypted, "Decrypted plaintext should match original")
		})
	}
}

// TestRSADecrypt_OAEP tests RSA-OAEP decryption with SHA256.
func TestRSADecrypt_OAEP(t *testing.T) {
	// Generate a test RSA key pair for mocking
	testRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate test RSA key")

	testPublicKeyBytes, err := x509.MarshalPKIXPublicKey(&testRSAKey.PublicKey)
	require.NoError(t, err, "Failed to marshal public key")

	tests := []struct {
		name      string
		attrs     *types.KeyAttributes
		plaintext []byte
		oaepOpts  *rsa.OAEPOptions
		setupMock func(*MockKMSClient, []byte)
		wantErr   bool
	}{
		{
			name: "decrypt RSA-2048 OAEP SHA256",
			attrs: &types.KeyAttributes{
				CN:           "test-decrypt-oaep-2048",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_ENCRYPTION,
				StoreType:    backend.STORE_AWSKMS,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			},
			plaintext: []byte("Test message for RSA-2048 OAEP SHA-256"),
			oaepOpts: &rsa.OAEPOptions{
				Hash: crypto.SHA256,
			},
			setupMock: func(m *MockKMSClient, plaintext []byte) {
				m.GetPublicKeyFunc = func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
					keySpec := kmstypes.KeySpecRsa2048
					keyUsage := kmstypes.KeyUsageTypeEncryptDecrypt
					return &kms.GetPublicKeyOutput{
						KeyId:     aws.String("test-key-oaep-2048"),
						KeySpec:   keySpec,
						KeyUsage:  keyUsage,
						PublicKey: testPublicKeyBytes,
					}, nil
				}

				m.DecryptFunc = func(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
					// Verify that OAEP algorithm is specified
					assert.Equal(t, kmstypes.EncryptionAlgorithmSpecRsaesOaepSha256, params.EncryptionAlgorithm)

					return &kms.DecryptOutput{
						Plaintext:           plaintext,
						KeyId:               aws.String("test-key-oaep-2048"),
						EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecRsaesOaepSha256,
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name: "decrypt RSA-3072 OAEP SHA256",
			attrs: &types.KeyAttributes{
				CN:           "test-decrypt-oaep-3072",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_ENCRYPTION,
				StoreType:    backend.STORE_AWSKMS,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 3072,
				},
			},
			plaintext: []byte("Test RSA-3072 OAEP SHA-256 decryption"),
			oaepOpts: &rsa.OAEPOptions{
				Hash: crypto.SHA256,
			},
			setupMock: func(m *MockKMSClient, plaintext []byte) {
				m.GetPublicKeyFunc = func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
					keySpec := kmstypes.KeySpecRsa3072
					keyUsage := kmstypes.KeyUsageTypeEncryptDecrypt
					return &kms.GetPublicKeyOutput{
						KeyId:     aws.String("test-key-oaep-3072"),
						KeySpec:   keySpec,
						KeyUsage:  keyUsage,
						PublicKey: testPublicKeyBytes,
					}, nil
				}

				m.DecryptFunc = func(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
					assert.Equal(t, kmstypes.EncryptionAlgorithmSpecRsaesOaepSha256, params.EncryptionAlgorithm)

					return &kms.DecryptOutput{
						Plaintext:           plaintext,
						KeyId:               aws.String("test-key-oaep-3072"),
						EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecRsaesOaepSha256,
					}, nil
				}
			},
			wantErr: false,
		},
		{
			name: "decrypt RSA-4096 OAEP SHA256",
			attrs: &types.KeyAttributes{
				CN:           "test-decrypt-oaep-4096",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_ENCRYPTION,
				StoreType:    backend.STORE_AWSKMS,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 4096,
				},
			},
			plaintext: []byte("Test RSA-4096 OAEP SHA-256"),
			oaepOpts: &rsa.OAEPOptions{
				Hash: crypto.SHA256,
			},
			setupMock: func(m *MockKMSClient, plaintext []byte) {
				m.GetPublicKeyFunc = func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
					keySpec := kmstypes.KeySpecRsa4096
					keyUsage := kmstypes.KeyUsageTypeEncryptDecrypt
					return &kms.GetPublicKeyOutput{
						KeyId:     aws.String("test-key-oaep-4096"),
						KeySpec:   keySpec,
						KeyUsage:  keyUsage,
						PublicKey: testPublicKeyBytes,
					}, nil
				}

				m.DecryptFunc = func(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
					assert.Equal(t, kmstypes.EncryptionAlgorithmSpecRsaesOaepSha256, params.EncryptionAlgorithm)

					return &kms.DecryptOutput{
						Plaintext:           plaintext,
						KeyId:               aws.String("test-key-oaep-4096"),
						EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecRsaesOaepSha256,
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
				Region:      "us-east-1",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}
			b, err := NewBackendWithClient(config, mockClient)
			require.NoError(t, err, "Failed to create backend")

			// Get decrypter
			decrypter, err := b.Decrypter(tt.attrs)
			require.NoError(t, err, "Failed to get Decrypter")
			require.NotNil(t, decrypter, "Decrypter should not be nil")

			// Encrypt with the public key using OAEP
			rsaPub, ok := decrypter.Public().(*rsa.PublicKey)
			require.True(t, ok, "Public key should be an RSA public key")

			label := []byte("")
			ciphertext, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, rsaPub, tt.plaintext, label)
			require.NoError(t, err, "Failed to encrypt with OAEP")

			// Decrypt using Decrypter interface with OAEP options
			decrypted, err := decrypter.Decrypt(rand.Reader, ciphertext, tt.oaepOpts)

			if tt.wantErr {
				assert.Error(t, err, "Expected error but got none")
				return
			}

			require.NoError(t, err, "Failed to decrypt")
			assert.Equal(t, tt.plaintext, decrypted, "Decrypted plaintext should match original")
		})
	}
}

// TestDecrypterRoundTrip tests full encrypt/decrypt round trip for various RSA configurations.
func TestDecrypterRoundTrip(t *testing.T) {
	// Generate test RSA keys for mocking
	testRSAKey2048, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA-2048 key")
	testPublicKey2048, err := x509.MarshalPKIXPublicKey(&testRSAKey2048.PublicKey)
	require.NoError(t, err, "Failed to marshal RSA-2048 public key")

	testRSAKey3072, err := rsa.GenerateKey(rand.Reader, 3072)
	require.NoError(t, err, "Failed to generate RSA-3072 key")
	testPublicKey3072, err := x509.MarshalPKIXPublicKey(&testRSAKey3072.PublicKey)
	require.NoError(t, err, "Failed to marshal RSA-3072 public key")

	tests := []struct {
		name          string
		attrs         *types.KeyAttributes
		plaintext     string
		testRSAKey    *rsa.PrivateKey
		testPublicKey []byte
		decryptOpts   crypto.DecrypterOpts
		encryptFunc   func(*rsa.PublicKey, []byte) ([]byte, error)
	}{
		{
			name: "RSA-2048 OAEP SHA256 round trip",
			attrs: &types.KeyAttributes{
				CN:           "roundtrip-oaep-2048",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_ENCRYPTION,
				StoreType:    backend.STORE_AWSKMS,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			},
			plaintext:     "Round trip test for OAEP SHA-256",
			testRSAKey:    testRSAKey2048,
			testPublicKey: testPublicKey2048,
			decryptOpts: &rsa.OAEPOptions{
				Hash: crypto.SHA256,
			},
			encryptFunc: func(pub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
				return rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, pub, plaintext, []byte(""))
			},
		},
		{
			name: "RSA-3072 OAEP SHA256 round trip",
			attrs: &types.KeyAttributes{
				CN:           "roundtrip-oaep-3072",
				KeyAlgorithm: x509.RSA,
				KeyType:      backend.KEY_TYPE_ENCRYPTION,
				StoreType:    backend.STORE_AWSKMS,
				Hash:         crypto.SHA256,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 3072,
				},
			},
			plaintext:     "Round trip for RSA-3072 OAEP",
			testRSAKey:    testRSAKey3072,
			testPublicKey: testPublicKey3072,
			decryptOpts: &rsa.OAEPOptions{
				Hash: crypto.SHA256,
			},
			encryptFunc: func(pub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
				return rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, pub, plaintext, []byte(""))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockKMSClient{}

			// Setup mock to return the test public key
			mockClient.GetPublicKeyFunc = func(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
				var keySpec kmstypes.KeySpec
				switch tt.attrs.RSAAttributes.KeySize {
				case 2048:
					keySpec = kmstypes.KeySpecRsa2048
				case 3072:
					keySpec = kmstypes.KeySpecRsa3072
				case 4096:
					keySpec = kmstypes.KeySpecRsa4096
				}

				return &kms.GetPublicKeyOutput{
					KeyId:     aws.String("roundtrip-key-id"),
					KeySpec:   keySpec,
					KeyUsage:  kmstypes.KeyUsageTypeEncryptDecrypt,
					PublicKey: tt.testPublicKey,
				}, nil
			}

			// Setup mock to perform actual decryption using test private key
			mockClient.DecryptFunc = func(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
				// Perform actual RSA decryption based on the algorithm
				// AWS KMS backend uses OAEP SHA256 for RSA encryption/decryption
				plaintext, err := rsa.DecryptOAEP(crypto.SHA256.New(), rand.Reader, tt.testRSAKey, params.CiphertextBlob, []byte(""))
				if err != nil {
					return nil, err
				}

				return &kms.DecryptOutput{
					Plaintext:           plaintext,
					KeyId:               aws.String("roundtrip-key-id"),
					EncryptionAlgorithm: params.EncryptionAlgorithm,
				}, nil
			}

			config := &Config{
				Region:      "us-east-1",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}
			b, err := NewBackendWithClient(config, mockClient)
			require.NoError(t, err, "Failed to create backend")

			// Get decrypter
			decrypter, err := b.Decrypter(tt.attrs)
			require.NoError(t, err, "Failed to get Decrypter")

			// Encrypt using public key
			rsaPub, ok := decrypter.Public().(*rsa.PublicKey)
			require.True(t, ok, "Public key should be RSA")

			plaintextBytes := []byte(tt.plaintext)
			ciphertext, err := tt.encryptFunc(rsaPub, plaintextBytes)
			require.NoError(t, err, "Encryption failed")

			// Decrypt using Decrypter interface
			decrypted, err := decrypter.Decrypt(rand.Reader, ciphertext, tt.decryptOpts)
			require.NoError(t, err, "Decryption failed")

			// Verify round trip
			assert.Equal(t, plaintextBytes, decrypted, "Round trip plaintext mismatch")
		})
	}
}
