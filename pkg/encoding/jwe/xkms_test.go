// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package jwe

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"testing"
)

// Mock keystore for testing
type mockKeyStore struct {
	publicKeys  map[string]crypto.PublicKey
	privateKeys map[string]crypto.Decrypter
}

func newMockKeyStore() *mockKeyStore {
	return &mockKeyStore{
		publicKeys:  make(map[string]crypto.PublicKey),
		privateKeys: make(map[string]crypto.Decrypter),
	}
}

func (m *mockKeyStore) AddRSAKey(keyID string, key *rsa.PrivateKey) {
	m.publicKeys[keyID] = &key.PublicKey
	m.privateKeys[keyID] = key
}

func (m *mockKeyStore) AddECDSAKey(keyID string, key *ecdsa.PrivateKey) {
	m.publicKeys[keyID] = &key.PublicKey
	// Store ECDSA key as ecdsaWrapper that implements crypto.Decrypter interface
	m.privateKeys[keyID] = &ecdsaWrapper{key: key}
}

// ecdsaWrapper wraps ecdsa.PrivateKey to implement crypto.Decrypter interface
// go-jose accepts *ecdsa.PrivateKey directly, but we need crypto.Decrypter for the interface
type ecdsaWrapper struct {
	key *ecdsa.PrivateKey
}

func (e *ecdsaWrapper) Public() crypto.PublicKey {
	return &e.key.PublicKey
}

func (e *ecdsaWrapper) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	// Not used for ECDH - go-jose handles ECDH internally when it sees *ecdsa.PrivateKey
	// This method exists only to satisfy the crypto.Decrypter interface
	return nil, fmt.Errorf("not implemented")
}

// GetPrivateKey returns the underlying ECDSA private key for direct use with go-jose
func (e *ecdsaWrapper) GetPrivateKey() *ecdsa.PrivateKey {
	return e.key
}

func (m *mockKeyStore) GetPublicKey(keyID string) (crypto.PublicKey, error) {
	key, ok := m.publicKeys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}
	return key, nil
}

func (m *mockKeyStore) GetDecrypter(keyID string) (crypto.Decrypter, error) {
	key, ok := m.privateKeys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}
	return key, nil
}

// Test XKMSEncrypter with RSA
func TestXKMSEncrypter_RSA(t *testing.T) {
	// Setup mock keystore
	keyStore := newMockKeyStore()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	keyStore.AddRSAKey("rsa-key-1", rsaKey)

	// Create xkms encrypter
	encrypter, err := NewXKMSEncrypter("RSA-OAEP-256", "A256GCM", keyStore.GetPublicKey)
	if err != nil {
		t.Fatalf("Failed to create xkms encrypter: %v", err)
	}

	plaintext := []byte("xKMS encryption test")

	// Encrypt with key ID
	jweString, err := encrypter.EncryptWithKeyID(plaintext, "rsa-key-1")
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify kid in header
	kid, err := ExtractKID(jweString)
	if err != nil {
		t.Fatalf("Failed to extract kid: %v", err)
	}

	if kid != "rsa-key-1" {
		t.Errorf("Expected kid 'rsa-key-1', got '%s'", kid)
	}

	// Create xkms decrypter
	decrypter := NewXKMSDecrypter(keyStore.GetDecrypter)

	// Decrypt with auto key ID
	decrypted, err := decrypter.DecryptWithAutoKeyID(jweString)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text doesn't match")
	}
}

// Test XKMSEncrypter with ECDSA
func TestXKMSEncrypter_ECDSA(t *testing.T) {
	// Setup mock keystore
	keyStore := newMockKeyStore()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	keyStore.AddECDSAKey("ec-key-1", ecKey)

	// Create xkms encrypter
	encrypter, err := NewXKMSEncrypter("ECDH-ES+A256KW", "A256GCM", keyStore.GetPublicKey)
	if err != nil {
		t.Fatalf("Failed to create xkms encrypter: %v", err)
	}

	plaintext := []byte("ECDH xkms test")

	// Encrypt with key ID
	jweString, err := encrypter.EncryptWithKeyID(plaintext, "ec-key-1")
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify kid in header
	kid, err := ExtractKID(jweString)
	if err != nil {
		t.Fatalf("Failed to extract kid: %v", err)
	}

	if kid != "ec-key-1" {
		t.Errorf("Expected kid 'ec-key-1', got '%s'", kid)
	}

	// Create xkms decrypter
	decrypter := NewXKMSDecrypter(keyStore.GetDecrypter)

	// Decrypt with auto key ID
	decrypted, err := decrypter.DecryptWithAutoKeyID(jweString)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text doesn't match")
	}
}

// Test XKMSDecrypter with explicit key ID
func TestXKMSDecrypter_ExplicitKeyID(t *testing.T) {
	// Setup mock keystore with multiple keys
	keyStore := newMockKeyStore()

	rsaKey1, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaKey2, _ := rsa.GenerateKey(rand.Reader, 2048)

	keyStore.AddRSAKey("rsa-key-1", rsaKey1)
	keyStore.AddRSAKey("rsa-key-2", rsaKey2)

	plaintext := []byte("Multi-key test")

	// Encrypt with key 1 (without kid in header)
	encrypter1, _ := NewEncrypter("RSA-OAEP", "A256GCM", &rsaKey1.PublicKey)
	jweString, err := encrypter1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Create xkms decrypter
	decrypter := NewXKMSDecrypter(keyStore.GetDecrypter)

	// Decrypt with explicit key ID
	decrypted, err := decrypter.DecryptWithKeyID(jweString, "rsa-key-1")
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text doesn't match")
	}

	// Try with wrong key - should fail
	_, err = decrypter.DecryptWithKeyID(jweString, "rsa-key-2")
	if err == nil {
		t.Error("Expected error when decrypting with wrong key")
	}
}

// Test XKMSEncrypter.Encrypt (without kid in header)
func TestXKMSEncrypter_EncryptWithoutKID(t *testing.T) {
	keyStore := newMockKeyStore()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyStore.AddRSAKey("rsa-key-1", rsaKey)

	encrypter, _ := NewXKMSEncrypter("RSA-OAEP", "A256GCM", keyStore.GetPublicKey)
	plaintext := []byte("Test without kid")

	// Encrypt without kid
	jweString, err := encrypter.Encrypt(plaintext, "rsa-key-1")
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify no kid in header
	kid, err := ExtractKID(jweString)
	if err != nil {
		t.Fatalf("Failed to extract kid: %v", err)
	}

	if kid != "" {
		t.Errorf("Expected empty kid, got '%s'", kid)
	}

	// Can still decrypt with explicit key ID
	decrypter := NewXKMSDecrypter(keyStore.GetDecrypter)
	decrypted, err := decrypter.DecryptWithKeyID(jweString, "rsa-key-1")
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text doesn't match")
	}
}

// Test XKMSDecrypter.Decrypt (alias for DecryptWithAutoKeyID)
func TestXKMSDecrypter_DecryptAlias(t *testing.T) {
	keyStore := newMockKeyStore()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyStore.AddRSAKey("rsa-key-1", rsaKey)

	encrypter, _ := NewXKMSEncrypter("RSA-OAEP", "A256GCM", keyStore.GetPublicKey)
	plaintext := []byte("Alias test")

	jweString, _ := encrypter.EncryptWithKeyID(plaintext, "rsa-key-1")

	decrypter := NewXKMSDecrypter(keyStore.GetDecrypter)

	// Use Decrypt alias
	decrypted, err := decrypter.Decrypt(jweString)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text doesn't match")
	}
}

// Test error cases for XKMSEncrypter
func TestXKMSEncrypter_Errors(t *testing.T) {
	t.Run("NilGetKeyFunction", func(t *testing.T) {
		_, err := NewXKMSEncrypter("RSA-OAEP", "A256GCM", nil)
		if err == nil {
			t.Error("Expected error for nil getKey function")
		}
	})

	t.Run("InvalidKeyAlgorithm", func(t *testing.T) {
		keyStore := newMockKeyStore()
		_, err := NewXKMSEncrypter("INVALID-ALG", "A256GCM", keyStore.GetPublicKey)
		if err == nil {
			t.Error("Expected error for invalid key algorithm")
		}
	})

	t.Run("InvalidContentEncryption", func(t *testing.T) {
		keyStore := newMockKeyStore()
		_, err := NewXKMSEncrypter("RSA-OAEP", "INVALID-ENC", keyStore.GetPublicKey)
		if err == nil {
			t.Error("Expected error for invalid content encryption")
		}
	})

	t.Run("EmptyKeyID", func(t *testing.T) {
		keyStore := newMockKeyStore()
		encrypter, _ := NewXKMSEncrypter("RSA-OAEP", "A256GCM", keyStore.GetPublicKey)
		_, err := encrypter.EncryptWithKeyID([]byte("test"), "")
		if err == nil {
			t.Error("Expected error for empty key ID")
		}
	})

	t.Run("KeyNotFound", func(t *testing.T) {
		keyStore := newMockKeyStore()
		encrypter, _ := NewXKMSEncrypter("RSA-OAEP", "A256GCM", keyStore.GetPublicKey)
		_, err := encrypter.EncryptWithKeyID([]byte("test"), "non-existent-key")
		if err == nil {
			t.Error("Expected error for non-existent key")
		}
	})
}

// Test error cases for XKMSDecrypter
func TestXKMSDecrypter_Errors(t *testing.T) {
	keyStore := newMockKeyStore()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyStore.AddRSAKey("rsa-key-1", rsaKey)

	t.Run("EmptyKeyID", func(t *testing.T) {
		decrypter := NewXKMSDecrypter(keyStore.GetDecrypter)
		_, err := decrypter.DecryptWithKeyID("some.jwe.string.here.now", "")
		if err == nil {
			t.Error("Expected error for empty key ID")
		}
	})

	t.Run("KeyNotFound", func(t *testing.T) {
		encrypter, _ := NewXKMSEncrypter("RSA-OAEP", "A256GCM", keyStore.GetPublicKey)
		jweString, _ := encrypter.EncryptWithKeyID([]byte("test"), "rsa-key-1")

		decrypter := NewXKMSDecrypter(keyStore.GetDecrypter)
		_, err := decrypter.DecryptWithKeyID(jweString, "non-existent-key")
		if err == nil {
			t.Error("Expected error for non-existent key")
		}
	})

	t.Run("MissingKIDInHeader", func(t *testing.T) {
		// Encrypt without kid
		encrypter, _ := NewEncrypter("RSA-OAEP", "A256GCM", &rsaKey.PublicKey)
		jweString, _ := encrypter.Encrypt([]byte("test"))

		decrypter := NewXKMSDecrypter(keyStore.GetDecrypter)
		_, err := decrypter.DecryptWithAutoKeyID(jweString)
		if err == nil {
			t.Error("Expected error when kid is missing from header")
		}
	})
}

// Test hardware-backed key simulation (crypto.Decrypter interface)
func TestXKMSDecrypter_CryptoDecrypter(t *testing.T) {
	// This tests that XKMSDecrypter works with crypto.Decrypter interface
	// which is what HSM/TPM implementations provide

	keyStore := newMockKeyStore()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyStore.AddRSAKey("hsm-key", rsaKey)

	plaintext := []byte("Hardware-backed key test")

	// Encrypt
	encrypter, _ := NewXKMSEncrypter("RSA-OAEP", "A256GCM", keyStore.GetPublicKey)
	jweString, _ := encrypter.EncryptWithKeyID(plaintext, "hsm-key")

	// Decrypt using crypto.Decrypter interface
	decrypter := NewXKMSDecrypter(keyStore.GetDecrypter)
	decrypted, err := decrypter.Decrypt(jweString)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text doesn't match")
	}
}

// Benchmark xkms operations
func BenchmarkXKMSEncryption(b *testing.B) {
	keyStore := newMockKeyStore()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyStore.AddRSAKey("bench-key", rsaKey)

	encrypter, _ := NewXKMSEncrypter("RSA-OAEP-256", "A256GCM", keyStore.GetPublicKey)
	plaintext := []byte("Benchmark test")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encrypter.EncryptWithKeyID(plaintext, "bench-key")
	}
}

func BenchmarkXKMSDecryption(b *testing.B) {
	keyStore := newMockKeyStore()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyStore.AddRSAKey("bench-key", rsaKey)

	encrypter, _ := NewXKMSEncrypter("RSA-OAEP-256", "A256GCM", keyStore.GetPublicKey)
	plaintext := []byte("Benchmark test")
	jweString, _ := encrypter.EncryptWithKeyID(plaintext, "bench-key")

	decrypter := NewXKMSDecrypter(keyStore.GetDecrypter)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = decrypter.DecryptWithAutoKeyID(jweString)
	}
}

// Test XKMSEncrypter.Encrypt error path
func TestXKMSEncrypter_EncryptErrors(t *testing.T) {
	keyStore := newMockKeyStore()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyStore.AddRSAKey("rsa-key-1", rsaKey)

	encrypter, _ := NewXKMSEncrypter("RSA-OAEP", "A256GCM", keyStore.GetPublicKey)

	t.Run("EmptyKeyID", func(t *testing.T) {
		_, err := encrypter.Encrypt([]byte("test"), "")
		if err == nil {
			t.Error("Expected error for empty key ID")
		}
	})

	t.Run("KeyNotFound", func(t *testing.T) {
		_, err := encrypter.Encrypt([]byte("test"), "non-existent")
		if err == nil {
			t.Error("Expected error for non-existent key")
		}
	})
}

// Test XKMSDecrypter error paths
func TestXKMSDecrypter_ErrorPaths(t *testing.T) {
	keyStore := newMockKeyStore()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyStore.AddRSAKey("rsa-key-1", rsaKey)

	t.Run("InvalidJWEString", func(t *testing.T) {
		decrypter := NewXKMSDecrypter(keyStore.GetDecrypter)
		_, err := decrypter.DecryptWithAutoKeyID("invalid.jwe.string")
		if err == nil {
			t.Error("Expected error for invalid JWE string")
		}
	})
}
