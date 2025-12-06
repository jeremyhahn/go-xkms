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

// TestKeyStore_Backend tests accessing the underlying backend
func TestKeyStore_Backend(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	backend := ks.Backend()
	if backend == nil {
		t.Fatal("Backend should not be nil")
	}

	if backend.Type() != types.BackendTypeSoftware {
		t.Errorf("Expected software backend, got %v", backend.Type())
	}
}

// TestKeyStore_CertStorage tests accessing the underlying certificate storage
func TestKeyStore_CertStorage(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	certStorage := ks.CertStorage()
	if certStorage == nil {
		t.Fatal("CertStorage should not be nil")
	}
}

// TestKeyStore_Close tests closing the keystore
func TestKeyStore_Close(t *testing.T) {
	ks := createTestKeyStore(t)

	// Generate a key before closing
	attrs := &types.KeyAttributes{
		CN:           "test-close",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StorePKCS8,
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

	// Close the keystore
	err = ks.Close()
	if err != nil {
		t.Fatalf("Failed to close keystore: %v", err)
	}

	// Operations after close should fail
	_, err = ks.GetKey(attrs)
	if err == nil {
		t.Error("Expected error when using closed keystore")
	}
}

// TestKeyStore_New_ErrorCases tests error handling in keystore creation
func TestKeyStore_New_ErrorCases(t *testing.T) {
	t.Run("NilBackend", func(t *testing.T) {
		certStorage := storage.New()
		_, err := keychain.New(&keychain.Config{
			Backend:     nil,
			CertStorage: certStorage,
		})
		if err == nil {
			t.Error("Expected error with nil backend")
		}
	})

	t.Run("NilCertStorage", func(t *testing.T) {
		_, err := keychain.New(&keychain.Config{
			Backend:     createTestKeyStore(t).Backend(),
			CertStorage: nil,
		})
		if err == nil {
			t.Error("Expected error with nil cert storage")
		}
	})
}

// TestKeyStore_RotateKey_AllAlgorithms tests key rotation for all algorithms
func TestKeyStore_RotateKey_AllAlgorithms(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func(ks keychain.KeyStore) (*types.KeyAttributes, error)
	}{
		{
			name: "RSA",
			setupFunc: func(ks keychain.KeyStore) (*types.KeyAttributes, error) {
				attrs := &types.KeyAttributes{
					CN:           "test-rotate-rsa",
					KeyType:      types.KeyTypeSigning,
					StoreType:    types.StorePKCS8,
					KeyAlgorithm: x509.RSA,
					RSAAttributes: &types.RSAAttributes{
						KeySize: 2048,
					},
					Hash: crypto.SHA256,
				}
				_, err := ks.GenerateRSA(attrs)
				return attrs, err
			},
		},
		{
			name: "ECDSA",
			setupFunc: func(ks keychain.KeyStore) (*types.KeyAttributes, error) {
				attrs := &types.KeyAttributes{
					CN:           "test-rotate-ecdsa",
					KeyType:      types.KeyTypeSigning,
					StoreType:    types.StorePKCS8,
					KeyAlgorithm: x509.ECDSA,
					ECCAttributes: &types.ECCAttributes{
						Curve: elliptic.P256(),
					},
					Hash: crypto.SHA256,
				}
				_, err := ks.GenerateECDSA(attrs)
				return attrs, err
			},
		},
		{
			name: "Ed25519",
			setupFunc: func(ks keychain.KeyStore) (*types.KeyAttributes, error) {
				attrs := &types.KeyAttributes{
					CN:           "test-rotate-ed25519",
					KeyType:      types.KeyTypeSigning,
					StoreType:    types.StorePKCS8,
					KeyAlgorithm: x509.Ed25519,
				}
				_, err := ks.GenerateEd25519(attrs)
				return attrs, err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := createTestKeyStore(t)
			defer ks.Close()

			// Setup initial key
			attrs, err := tt.setupFunc(ks)
			if err != nil {
				t.Fatalf("Failed to setup key: %v", err)
			}

			// Rotate the key
			newKey, err := ks.RotateKey(attrs)
			if err != nil {
				t.Fatalf("Failed to rotate key: %v", err)
			}

			if newKey == nil {
				t.Fatal("Rotated key is nil")
			}

			// Verify new key exists
			retrievedKey, err := ks.GetKey(attrs)
			if err != nil {
				t.Fatalf("Failed to retrieve rotated key: %v", err)
			}

			if retrievedKey == nil {
				t.Fatal("Retrieved key is nil")
			}
		})
	}
}

// TestKeyStore_RotateKey_InvalidAlgorithm tests rotating with an unsupported algorithm
func TestKeyStore_RotateKey_InvalidAlgorithm(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	// Create attributes with an invalid algorithm
	attrs := &types.KeyAttributes{
		CN:           "test-rotate-invalid",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.PublicKeyAlgorithm(999), // Invalid algorithm
	}

	// Try to rotate - should fail
	_, err := ks.RotateKey(attrs)
	if err == nil {
		t.Error("Expected error when rotating key with invalid algorithm")
	}
}

// TestKeyStore_GetDecrypterByID_InvalidKeyType tests getting decrypter with wrong key type
func TestKeyStore_GetDecrypterByID_InvalidKeyType(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	// Generate an ECDSA key (not suitable for decryption)
	attrs := &types.KeyAttributes{
		CN:           "test-decrypter-ecdsa",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
		Hash: crypto.SHA256,
	}

	_, err := ks.GenerateECDSA(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Try to get decrypter for ECDSA key (should fail)
	keyID := "software:signing:ecdsa-p256:test-decrypter-ecdsa"
	_, err = ks.GetDecrypterByID(keyID)
	if err == nil {
		t.Error("Expected error when getting decrypter for ECDSA key")
	}
}

// TestKeyStore_GetTLSCertificate_MissingChain tests TLS certificate with missing chain
func TestKeyStore_GetTLSCertificate_MissingChain(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	// Generate key
	keyID := "test-tls-no-chain"
	attrs := &types.KeyAttributes{
		CN:           keyID,
		KeyType:      types.KeyTypeTLS,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	key, err := ks.GenerateRSA(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create and save just the certificate (no chain)
	cert := createSelfSignedCert(t, key, keyID)
	err = ks.SaveCert(keyID, cert)
	if err != nil {
		t.Fatalf("Failed to save certificate: %v", err)
	}

	// Get TLS certificate (should work even without chain)
	tlsCert, err := ks.GetTLSCertificate(keyID, attrs)
	if err != nil {
		t.Fatalf("Failed to get TLS certificate: %v", err)
	}

	// Should have at least the leaf certificate
	if len(tlsCert.Certificate) == 0 {
		t.Error("Expected at least one certificate in chain")
	}

	if tlsCert.Leaf == nil {
		t.Error("Expected leaf certificate")
	}
}

// TestKeyStore_GetTLSCertificate_ErrorCases tests TLS certificate error handling
func TestKeyStore_GetTLSCertificate_ErrorCases(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	attrs := &types.KeyAttributes{
		CN:           "test-tls-errors",
		KeyType:      types.KeyTypeTLS,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	t.Run("EmptyKeyID", func(t *testing.T) {
		_, err := ks.GetTLSCertificate("", attrs)
		if err == nil {
			t.Error("Expected error with empty key ID")
		}
	})

	t.Run("NilAttributes", func(t *testing.T) {
		_, err := ks.GetTLSCertificate("test-tls-errors", nil)
		if err == nil {
			t.Error("Expected error with nil attributes")
		}
	})

	t.Run("MissingKey", func(t *testing.T) {
		_, err := ks.GetTLSCertificate("nonexistent", attrs)
		if err == nil {
			t.Error("Expected error with nonexistent key")
		}
	})
}

// TestKeyStore_DeleteCert_NonExistent tests deleting a certificate that doesn't exist
func TestKeyStore_DeleteCert_NonExistent(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	err := ks.DeleteCert("nonexistent-cert")
	if err == nil {
		t.Error("Expected error when deleting nonexistent certificate")
	}
}

// TestPassword tests password helper functions
func TestPassword(t *testing.T) {
	t.Run("NewClearPassword", func(t *testing.T) {
		passwordBytes := []byte("test-password")
		password := keychain.NewClearPassword(passwordBytes)

		if password == nil {
			t.Fatal("Password should not be nil")
		}

		// Verify password string
		passwordStr, err := password.String()
		if err != nil {
			t.Fatalf("Failed to get password string: %v", err)
		}
		if passwordStr != string(passwordBytes) {
			t.Error("Password string does not match")
		}

		// Verify password bytes
		passwordBytesRetrieved, err := password.Bytes()
		if err != nil {
			t.Fatalf("Failed to get password bytes: %v", err)
		}
		if string(passwordBytesRetrieved) != string(passwordBytes) {
			t.Error("Password bytes do not match")
		}

		// Test zeroize (cast to *ClearPassword to access Zeroize method)
		if clearPassword, ok := password.(*keychain.ClearPassword); ok {
			clearPassword.Zeroize()
			passwordBytesAfterZeroize, err := clearPassword.Bytes()
			if err != nil {
				t.Fatalf("Failed to get password bytes after zeroize: %v", err)
			}
			if string(passwordBytesAfterZeroize) == string(passwordBytes) {
				t.Error("Password should be zeroized")
			}
		} else {
			t.Error("Password is not *ClearPassword")
		}
	})

	t.Run("NewClearPasswordFromString", func(t *testing.T) {
		passwordStr := "test-password-string"
		password := keychain.NewClearPasswordFromString(passwordStr)

		if password == nil {
			t.Fatal("Password should not be nil")
		}

		retrievedPasswordStr, err := password.String()
		if err != nil {
			t.Fatalf("Failed to get password string: %v", err)
		}
		if retrievedPasswordStr != passwordStr {
			t.Error("Password string does not match")
		}
	})
}

// TestVersion tests version function
func TestVersion(t *testing.T) {
	version := keychain.Version()
	if version == "" {
		t.Error("Version should not be empty")
	}
}

// TestKeyID_String tests KeyID String method
func TestKeyID_String(t *testing.T) {
	keyIDStr := "software:signing:rsa:test-key"
	keyID := keychain.KeyID(keyIDStr)

	if keyID.String() != keyIDStr {
		t.Errorf("Expected %s, got %s", keyIDStr, keyID.String())
	}
}

// TestKeyStore_GetDecrypterByID_P521 tests decrypter with P-521 curve
func TestKeyStore_GetDecrypterByID_P521(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	// Generate an ECDSA P-521 key
	attrs := &types.KeyAttributes{
		CN:           "test-p521",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P521(),
		},
		Hash: crypto.SHA256,
	}

	_, err := ks.GenerateECDSA(attrs)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Try to get decrypter (should fail as ECDSA keys don't support decryption)
	keyID := "software:signing:ecdsa-p521:test-p521"
	_, err = ks.GetDecrypterByID(keyID)
	if err == nil {
		t.Error("Expected error when getting decrypter for ECDSA key")
	}
}

// TestKeyStore_SaveCertChain_EmptyChain tests saving empty certificate chain
func TestKeyStore_SaveCertChain_EmptyChain(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	err := ks.SaveCertChain("test-empty-chain", []*x509.Certificate{})
	if err == nil {
		t.Error("Expected error when saving empty certificate chain")
	}
}

// TestKeyStore_SaveCert_NilCertificate tests saving nil certificate
func TestKeyStore_SaveCert_NilCertificate(t *testing.T) {
	ks := createTestKeyStore(t)
	defer ks.Close()

	err := ks.SaveCert("test-nil-cert", nil)
	if err == nil {
		t.Error("Expected error when saving nil certificate")
	}
}
