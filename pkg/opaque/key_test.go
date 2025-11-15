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

package opaque

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// mockKeyStore implements a minimal KeyStorer for testing
type mockKeyStore struct {
	getKeyFunc    func(*types.KeyAttributes) (crypto.PrivateKey, error)
	signerFunc    func(*types.KeyAttributes) (crypto.Signer, error)
	decrypterFunc func(*types.KeyAttributes) (crypto.Decrypter, error)
}

func (m *mockKeyStore) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if m.getKeyFunc != nil {
		return m.getKeyFunc(attrs)
	}
	return nil, errors.New("not implemented")
}

func (m *mockKeyStore) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	if m.signerFunc != nil {
		return m.signerFunc(attrs)
	}
	return nil, errors.New("not implemented")
}

func (m *mockKeyStore) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	if m.decrypterFunc != nil {
		return m.decrypterFunc(attrs)
	}
	return nil, errors.New("not implemented")
}

// TestNewOpaqueKey_ValidInputs tests successful creation with valid parameters
func TestNewOpaqueKey_ValidInputs(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	tests := []struct {
		name string
		hash crypto.Hash
	}{
		{
			name: "SHA256",
			hash: crypto.SHA256,
		},
		{
			name: "SHA384",
			hash: crypto.SHA384,
		},
		{
			name: "SHA512",
			hash: crypto.SHA512,
		},
		{
			name: "SHA3_256",
			hash: crypto.SHA3_256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
				Hash:         tt.hash,
			}

			keyStore := &mockKeyStore{}
			key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if key == nil {
				t.Fatal("expected non-nil key")
			}

			// Verify the key attributes match
			if key.KeyAttributes() != attrs {
				t.Error("key attributes mismatch")
			}

			// Verify the public key matches
			if key.Public() != &privKey.PublicKey {
				t.Error("public key mismatch")
			}
		})
	}
}

// TestNewOpaqueKey_InvalidInputs tests error paths for invalid parameters
func TestNewOpaqueKey_InvalidInputs(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	tests := []struct {
		name     string
		keyStore KeyStorer
		attrs    *types.KeyAttributes
		pub      crypto.PublicKey
		wantErr  error
	}{
		{
			name:     "nil keystore",
			keyStore: nil,
			attrs:    attrs,
			pub:      &privKey.PublicKey,
			wantErr:  ErrKeyStoreRequired,
		},
		{
			name:     "nil attributes",
			keyStore: &mockKeyStore{},
			attrs:    nil,
			pub:      &privKey.PublicKey,
			wantErr:  ErrInvalidKeyAttributes,
		},
		{
			name:     "nil public key",
			keyStore: &mockKeyStore{},
			attrs:    attrs,
			pub:      nil,
			wantErr:  ErrInvalidPublicKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := NewOpaqueKey(tt.keyStore, tt.attrs, tt.pub)
			if err == nil {
				t.Fatalf("expected error %v, got nil", tt.wantErr)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("expected error %v, got %v", tt.wantErr, err)
			}
			if key != nil {
				t.Error("expected nil key on error")
			}
		})
	}
}

// TestOpaquePublic tests the Public() method
func TestOpaquePublic(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	key, err := NewOpaqueKey(&mockKeyStore{}, attrs, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	pub := key.Public()
	if pub == nil {
		t.Fatal("Public() returned nil")
	}

	if pub != &privKey.PublicKey {
		t.Error("Public() returned different public key")
	}
}

// TestOpaqueSign_RSA tests the Sign() method with RSA keys
func TestOpaqueSign_RSA(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	testData := []byte("test data to sign")

	tests := []struct {
		name     string
		hash     crypto.Hash
		wantErr  bool
		errCheck func(error) bool
	}{
		{
			name:    "SHA256",
			hash:    crypto.SHA256,
			wantErr: false,
		},
		{
			name:    "SHA384",
			hash:    crypto.SHA384,
			wantErr: false,
		},
		{
			name:    "SHA512",
			hash:    crypto.SHA512,
			wantErr: false,
		},
		{
			name:    "signer error",
			hash:    crypto.SHA256,
			wantErr: true,
			errCheck: func(err error) bool {
				return err.Error() == "signer error"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
				Hash:         crypto.SHA256,
			}

			var keyStore *mockKeyStore
			if tt.wantErr && tt.errCheck != nil {
				keyStore = &mockKeyStore{
					signerFunc: func(*types.KeyAttributes) (crypto.Signer, error) {
						return nil, errors.New("signer error")
					},
				}
			} else {
				keyStore = &mockKeyStore{
					signerFunc: func(*types.KeyAttributes) (crypto.Signer, error) {
						return privKey, nil
					},
				}
			}

			key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
			if err != nil {
				t.Fatalf("failed to create opaque key: %v", err)
			}

			// Hash the test data
			hasher := tt.hash.New()
			hasher.Write(testData)
			hashed := hasher.Sum(nil)

			signature, err := key.Sign(rand.Reader, hashed, tt.hash)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errCheck != nil && !tt.errCheck(err) {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(signature) == 0 {
				t.Error("expected non-empty signature")
			}

			// Verify signature
			err = rsa.VerifyPKCS1v15(&privKey.PublicKey, tt.hash, hashed, signature)
			if err != nil {
				t.Errorf("signature verification failed: %v", err)
			}
		})
	}
}

// TestOpaqueSign_ECDSA tests the Sign() method with ECDSA keys
func TestOpaqueSign_ECDSA(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
		hash  crypto.Hash
	}{
		{
			name:  "P256_SHA256",
			curve: elliptic.P256(),
			hash:  crypto.SHA256,
		},
		{
			name:  "P384_SHA384",
			curve: elliptic.P384(),
			hash:  crypto.SHA384,
		},
		{
			name:  "P521_SHA512",
			curve: elliptic.P521(),
			hash:  crypto.SHA512,
		},
	}

	testData := []byte("test data")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate ECDSA key: %v", err)
			}

			attrs := &types.KeyAttributes{
				CN:           "test-ecdsa-key",
				KeyAlgorithm: x509.ECDSA,
				Hash:         crypto.SHA256,
			}

			keyStore := &mockKeyStore{
				signerFunc: func(*types.KeyAttributes) (crypto.Signer, error) {
					return privKey, nil
				},
			}

			key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
			if err != nil {
				t.Fatalf("failed to create opaque key: %v", err)
			}

			// Hash the test data
			hasher := tt.hash.New()
			hasher.Write(testData)
			hashed := hasher.Sum(nil)

			signature, err := key.Sign(rand.Reader, hashed, tt.hash)
			if err != nil {
				t.Fatalf("Sign() failed: %v", err)
			}
			if len(signature) == 0 {
				t.Error("expected non-empty signature")
			}

			// Verify signature
			if !ecdsa.VerifyASN1(&privKey.PublicKey, hashed, signature) {
				t.Error("ECDSA signature verification failed")
			}
		})
	}
}

// TestOpaqueSign_Ed25519 tests the Sign() method with Ed25519 keys
func TestOpaqueSign_Ed25519(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-ed25519-key",
		KeyAlgorithm: x509.Ed25519,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		signerFunc: func(*types.KeyAttributes) (crypto.Signer, error) {
			return privKey, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, pubKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	testData := []byte("test message")

	// Ed25519 doesn't pre-hash, but we test with the data directly
	signature, err := key.Sign(rand.Reader, testData, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}
	if len(signature) != ed25519.SignatureSize {
		t.Errorf("expected signature size %d, got %d", ed25519.SignatureSize, len(signature))
	}

	// Verify signature
	if !ed25519.Verify(pubKey, testData, signature) {
		t.Error("Ed25519 signature verification failed")
	}
}

// TestOpaqueDecrypt_RSA tests the Decrypt() method with RSA keys
func TestOpaqueDecrypt_RSA(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	plaintext := []byte("secret message")
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &privKey.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt test data: %v", err)
	}

	tests := []struct {
		name     string
		opts     crypto.DecrypterOpts
		wantErr  bool
		errCheck func(error) bool
	}{
		{
			name:    "nil opts",
			opts:    nil,
			wantErr: false,
		},
		{
			name:    "decrypter error",
			opts:    nil,
			wantErr: true,
			errCheck: func(err error) bool {
				return err.Error() == "decrypter error"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
				Hash:         crypto.SHA256,
			}

			var keyStore *mockKeyStore
			if tt.wantErr && tt.errCheck != nil {
				keyStore = &mockKeyStore{
					decrypterFunc: func(*types.KeyAttributes) (crypto.Decrypter, error) {
						return nil, errors.New("decrypter error")
					},
				}
			} else {
				keyStore = &mockKeyStore{
					decrypterFunc: func(*types.KeyAttributes) (crypto.Decrypter, error) {
						return privKey, nil
					},
				}
			}

			key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
			if err != nil {
				t.Fatalf("failed to create opaque key: %v", err)
			}

			decrypted, err := key.Decrypt(rand.Reader, ciphertext, tt.opts)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errCheck != nil && !tt.errCheck(err) {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(decrypted) != string(plaintext) {
				t.Errorf("decryption mismatch: got %q, want %q", decrypted, plaintext)
			}
		})
	}
}

// TestOpaqueDecrypt_OAEP tests decryption with OAEP padding
func TestOpaqueDecrypt_OAEP(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	plaintext := []byte("secret with OAEP")
	ciphertext, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, &privKey.PublicKey, plaintext, nil)
	if err != nil {
		t.Fatalf("failed to encrypt test data: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		decrypterFunc: func(*types.KeyAttributes) (crypto.Decrypter, error) {
			return privKey, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	opts := &rsa.OAEPOptions{Hash: crypto.SHA256}
	decrypted, err := key.Decrypt(rand.Reader, ciphertext, opts)
	if err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("decryption mismatch: got %q, want %q", decrypted, plaintext)
	}
}

// TestOpaqueEqual tests the Equal() method
func TestOpaqueEqual(t *testing.T) {
	privKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key 1: %v", err)
	}

	privKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key 2: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	tests := []struct {
		name      string
		getKeyErr bool
		otherKey  crypto.PrivateKey
		wantEqual bool
	}{
		{
			name:      "same key",
			getKeyErr: false,
			otherKey:  privKey1,
			wantEqual: true,
		},
		{
			name:      "different key",
			getKeyErr: false,
			otherKey:  privKey2,
			wantEqual: false,
		},
		{
			name:      "getKey error",
			getKeyErr: true,
			otherKey:  privKey1,
			wantEqual: false,
		},
		{
			name:      "non-signer key",
			getKeyErr: false,
			otherKey:  struct{}{}, // Not a crypto.PrivateKey with Equal
			wantEqual: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var keyStore *mockKeyStore
			if tt.getKeyErr {
				keyStore = &mockKeyStore{
					getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
						return nil, errors.New("get key error")
					},
				}
			} else {
				keyStore = &mockKeyStore{
					getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
						return privKey1, nil
					},
				}
			}

			key, err := NewOpaqueKey(keyStore, attrs, &privKey1.PublicKey)
			if err != nil {
				t.Fatalf("failed to create opaque key: %v", err)
			}

			equal := key.Equal(tt.otherKey)
			if equal != tt.wantEqual {
				t.Errorf("Equal() = %v, want %v", equal, tt.wantEqual)
			}
		})
	}
}

// TestOpaqueEqual_PublicKeyFallback tests Equal() fallback to public key comparison
func TestOpaqueEqual_PublicKeyFallback(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	// Create a different key for comparison
	otherPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate other key: %v", err)
	}

	// Create a mock key that doesn't implement Equal
	type mockPrivKey struct {
		crypto.Signer
		pub crypto.PublicKey
	}

	mockKey := &mockPrivKey{
		pub: &privKey.PublicKey,
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			// Return a key without Equal method
			return mockKey, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Test with same public key - should use pointer comparison and return true
	equal := key.Equal(privKey)
	if !equal {
		t.Error("Expected true when comparing keys with same public key pointer")
	}

	// Test with different key - should return false
	equal = key.Equal(otherPrivKey)
	if equal {
		t.Error("Expected false when comparing with different key")
	}
}

// TestOpaqueDigest tests the Digest() method with different hash algorithms
func TestOpaqueDigest(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	testData := []byte("data to hash")

	tests := []struct {
		name         string
		hash         crypto.Hash
		expectedSize int
		wantErr      bool
	}{
		{
			name:         "SHA256",
			hash:         crypto.SHA256,
			expectedSize: 32,
			wantErr:      false,
		},
		{
			name:         "SHA384",
			hash:         crypto.SHA384,
			expectedSize: 48,
			wantErr:      false,
		},
		{
			name:         "SHA512",
			hash:         crypto.SHA512,
			expectedSize: 64,
			wantErr:      false,
		},
		{
			name:         "SHA3_256",
			hash:         crypto.SHA3_256,
			expectedSize: 32,
			wantErr:      false,
		},
		{
			name:         "SHA3_384",
			hash:         crypto.SHA3_384,
			expectedSize: 48,
			wantErr:      false,
		},
		{
			name:         "SHA3_512",
			hash:         crypto.SHA3_512,
			expectedSize: 64,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
				Hash:         tt.hash,
			}

			key, err := NewOpaqueKey(&mockKeyStore{}, attrs, &privKey.PublicKey)
			if err != nil {
				t.Fatalf("failed to create opaque key: %v", err)
			}

			digest, err := key.Digest(testData)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(digest) != tt.expectedSize {
				t.Errorf("expected digest size %d, got %d", tt.expectedSize, len(digest))
			}

			// Verify digest is correct
			hasher := tt.hash.New()
			hasher.Write(testData)
			expectedDigest := hasher.Sum(nil)
			if string(digest) != string(expectedDigest) {
				t.Error("digest mismatch")
			}
		})
	}
}

// TestOpaqueDigest_EmptyData tests Digest with empty data
func TestOpaqueDigest_EmptyData(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	key, err := NewOpaqueKey(&mockKeyStore{}, attrs, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	digest, err := key.Digest([]byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(digest) == 0 {
		t.Error("expected non-empty digest even for empty data")
	}

	// Verify it's the hash of empty data
	hasher := crypto.SHA256.New()
	hasher.Write([]byte{})
	expected := hasher.Sum(nil)
	if string(digest) != string(expected) {
		t.Error("digest mismatch for empty data")
	}
}

// TestOpaqueKeyAttributes tests the KeyAttributes() method
func TestOpaqueKeyAttributes(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_SW,
	}

	key, err := NewOpaqueKey(&mockKeyStore{}, attrs, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	gotAttrs := key.KeyAttributes()
	if gotAttrs == nil {
		t.Fatal("KeyAttributes() returned nil")
	}
	if gotAttrs.CN != attrs.CN {
		t.Errorf("CN mismatch: got %q, want %q", gotAttrs.CN, attrs.CN)
	}
	if gotAttrs.KeyAlgorithm != attrs.KeyAlgorithm {
		t.Errorf("KeyAlgorithm mismatch: got %v, want %v", gotAttrs.KeyAlgorithm, attrs.KeyAlgorithm)
	}
	if gotAttrs.Hash != attrs.Hash {
		t.Errorf("Hash mismatch: got %v, want %v", gotAttrs.Hash, attrs.Hash)
	}
	if gotAttrs.KeyType != attrs.KeyType {
		t.Errorf("KeyType mismatch: got %v, want %v", gotAttrs.KeyType, attrs.KeyType)
	}
}

// TestOpaqueInterfaces verifies the opaque key implements required interfaces
func TestOpaqueInterfaces(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	key, err := NewOpaqueKey(&mockKeyStore{}, attrs, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Test crypto.PrivateKey interface
	var _ crypto.PrivateKey = key

	// Test crypto.Signer interface
	var _ crypto.Signer = key

	// Test crypto.Decrypter interface
	var _ crypto.Decrypter = key

	// Test OpaqueKey interface
	var _ OpaqueKey = key

	t.Log("All interfaces implemented correctly")
}

// TestOpaqueSign_WithNilRand tests signing with nil random source
func TestOpaqueSign_WithNilRand(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		signerFunc: func(*types.KeyAttributes) (crypto.Signer, error) {
			return privKey, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	testData := []byte("test data")
	hasher := crypto.SHA256.New()
	hasher.Write(testData)
	hashed := hasher.Sum(nil)

	// Signing with nil rand should still work (deterministic signing)
	signature, err := key.Sign(nil, hashed, crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() with nil rand failed: %v", err)
	}
	if len(signature) == 0 {
		t.Error("expected non-empty signature")
	}
}

// TestOpaqueSign_WithNilDigest tests signing with nil digest
func TestOpaqueSign_WithNilDigest(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		signerFunc: func(*types.KeyAttributes) (crypto.Signer, error) {
			return privKey, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Signing with nil digest should fail at the crypto level
	_, err = key.Sign(rand.Reader, nil, crypto.SHA256)
	if err == nil {
		t.Error("expected error when signing nil digest")
	}
}

// TestOpaqueDecrypt_WithEmptyCiphertext tests decryption with empty ciphertext
func TestOpaqueDecrypt_WithEmptyCiphertext(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		decrypterFunc: func(*types.KeyAttributes) (crypto.Decrypter, error) {
			return privKey, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Decrypting empty ciphertext should fail
	_, err = key.Decrypt(rand.Reader, []byte{}, nil)
	if err == nil {
		t.Error("expected error when decrypting empty ciphertext")
	}
}

// TestMockKeyStore_NotImplemented tests the mock keystore's default behavior
func TestMockKeyStore_NotImplemented(t *testing.T) {
	mock := &mockKeyStore{}
	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.RSA,
	}

	// Test GetKey returns error when not implemented
	_, err := mock.GetKey(attrs)
	if err == nil {
		t.Error("expected error from unimplemented GetKey")
	}

	// Test Signer returns error when not implemented
	_, err = mock.Signer(attrs)
	if err == nil {
		t.Error("expected error from unimplemented Signer")
	}

	// Test Decrypter returns error when not implemented
	_, err = mock.Decrypter(attrs)
	if err == nil {
		t.Error("expected error from unimplemented Decrypter")
	}
}

// TestOpaqueEqual_DifferentPointers tests Equal() with different pointer instances
func TestOpaqueEqual_DifferentPointers(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	// Create a custom signer that returns a different public key instance
	type customSigner struct {
		*rsa.PrivateKey
	}

	customKey := &customSigner{PrivateKey: privKey}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			return privKey, nil
		},
	}

	// Create opaque key with one public key instance
	key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Compare with the custom signer - should compare the keys themselves
	equal := key.Equal(customKey)
	if equal {
		t.Error("Expected false since publicKeysEqual always returns false")
	}
}

// TestErrors tests that all error variables are defined correctly
func TestErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"ErrKeyStoreRequired", ErrKeyStoreRequired, "opaque: keystore is required"},
		{"ErrInvalidKeyAttributes", ErrInvalidKeyAttributes, "opaque: invalid key attributes"},
		{"ErrInvalidPublicKey", ErrInvalidPublicKey, "opaque: invalid public key"},
		{"ErrSignerNotSupported", ErrSignerNotSupported, "opaque: signer not supported by backend"},
		{"ErrDecrypterNotSupported", ErrDecrypterNotSupported, "opaque: decrypter not supported by backend"},
		{"ErrInvalidHashFunction", ErrInvalidHashFunction, "opaque: invalid or unavailable hash function"},
		{"ErrEqualNotSupported", ErrEqualNotSupported, "opaque: equality check not supported"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Error("error is nil")
				return
			}
			if tt.err.Error() != tt.want {
				t.Errorf("error message = %q, want %q", tt.err.Error(), tt.want)
			}
		})
	}
}

// TestOpaqueDigest_LargeData tests Digest with very large data
func TestOpaqueDigest_LargeData(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	key, err := NewOpaqueKey(&mockKeyStore{}, attrs, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Create 5MB of data
	largeData := make([]byte, 5*1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	digest, err := key.Digest(largeData)
	if err != nil {
		t.Fatalf("Digest() with large data failed: %v", err)
	}
	if len(digest) != 32 {
		t.Errorf("expected digest size 32, got %d", len(digest))
	}

	// Verify digest is correct
	hasher := crypto.SHA256.New()
	hasher.Write(largeData)
	expected := hasher.Sum(nil)
	if string(digest) != string(expected) {
		t.Error("Digest() mismatch for large data")
	}
}

// TestOpaqueEqual_WithNonEqualableKey tests Equal with a key that doesn't implement Equal
func TestOpaqueEqual_WithNonEqualableKey(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	// Create a struct that doesn't implement Equal but is a crypto.Signer
	type nonEqualableKey struct {
		*rsa.PrivateKey
	}

	nonEqualKey := &nonEqualableKey{PrivateKey: privKey}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			return nonEqualKey, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Test Equal falls back to public key comparison
	equal := key.Equal(privKey)
	// Since publicKeysEqual returns false and the keys have the same public key pointer
	// the first comparison (o.pub == xPub) should be true
	if !equal {
		t.Error("Expected true when comparing with same public key")
	}
}

// TestPublicKeysEqual_ECDSA tests publicKeysEqual function with ECDSA keys
func TestPublicKeysEqual_ECDSA(t *testing.T) {
	// Generate ECDSA keys on the same curve
	privKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate first ECDSA key: %v", err)
	}

	privKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate second ECDSA key: %v", err)
	}

	// Create a key with different curve
	privKey3, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate third ECDSA key with P384: %v", err)
	}

	tests := []struct {
		name       string
		testKey    *ecdsa.PrivateKey
		compareKey *ecdsa.PrivateKey
		wantEqual  bool
	}{
		{
			name:       "different ECDSA keys different values",
			testKey:    privKey1,
			compareKey: privKey2,
			wantEqual:  false,
		},
		{
			name:       "ECDSA P256 vs P384 different curves",
			testKey:    privKey1,
			compareKey: privKey3,
			wantEqual:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-ecdsa-key",
				KeyAlgorithm: x509.ECDSA,
				Hash:         crypto.SHA256,
			}

			// Create a wrapper that doesn't implement Equal method by NOT embedding
			// This forces the code to use publicKeysEqual
			type wrappedECDSAKey struct {
				key *ecdsa.PrivateKey
			}

			// Make it a Signer so it can be used with Equal()
			wrappedKey := &wrappedECDSAKey{key: tt.testKey}

			keyStore := &mockKeyStore{
				getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
					// Return wrapped key which doesn't have Equal method
					return wrappedKey, nil
				},
			}

			key, err := NewOpaqueKey(keyStore, attrs, &tt.testKey.PublicKey)
			if err != nil {
				t.Fatalf("failed to create opaque key: %v", err)
			}

			// Call Equal with a different ECDSA key
			// Since the key from keyStore is wrapped (doesn't have Equal),
			// it will fall through to publicKeysEqual at line 172
			equal := key.Equal(tt.compareKey)

			if equal != tt.wantEqual {
				t.Errorf("Equal() = %v, want %v", equal, tt.wantEqual)
			}
		})
	}
}

// TestPublicKeysEqual_Ed25519 tests publicKeysEqual function with Ed25519 keys
// This test uses the Equal() method to indirectly test publicKeysEqual
// Note: We test using RSA comparison because comparing ed25519.PublicKey (which is a slice)
// with == at line 172 would cause a panic. The publicKeysEqual function will be reached
// when comparing different key types.
func TestPublicKeysEqual_Ed25519(t *testing.T) {
	// Test that publicKeysEqual is called for Ed25519 keys when comparing with other types
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-ed25519-key",
		KeyAlgorithm: x509.Ed25519,
		Hash:         crypto.SHA256,
	}

	// Create a wrapper that doesn't implement Equal method by NOT embedding
	// This forces the code to use publicKeysEqual
	type wrappedEd25519Key struct {
		key ed25519.PrivateKey
	}

	wrappedKey := &wrappedEd25519Key{key: privKey}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			// Return wrapped key which doesn't have Equal method
			return wrappedKey, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, pubKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Call Equal with an RSA key
	// Since the key from keyStore is wrapped (doesn't have Equal),
	// it will fall through to publicKeysEqual at line 172
	// This will hit the Ed25519 case in publicKeysEqual when it tries to
	// cast the RSA public key to ed25519.PublicKey (which will fail the ok check)
	if key.Equal(rsaKey) {
		t.Error("Expected false when comparing Ed25519 with RSA key")
	}
}

// TestOpaqueEqual_WithECDSAKeys tests Equal with ECDSA key comparisons
func TestOpaqueEqual_WithECDSAKeys(t *testing.T) {
	// Generate two different ECDSA keys
	ecdsaKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key 1: %v", err)
	}

	ecdsaKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key 2: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			return ecdsaKey1, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &ecdsaKey1.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Test with same ECDSA key - should use key.Equal
	if !key.Equal(ecdsaKey1) {
		t.Error("Expected true when comparing with same ECDSA key")
	}

	// Test with different ECDSA key - publicKeysEqual should be called
	if key.Equal(ecdsaKey2) {
		t.Error("Expected false when comparing with different ECDSA key")
	}
}

// TestOpaqueEqual_WithEd25519Keys tests Equal with Ed25519 key comparisons
func TestOpaqueEqual_WithEd25519Keys(t *testing.T) {
	// Generate two different Ed25519 keys
	pubKey1, privKey1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key 1: %v", err)
	}

	_, privKey2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key 2: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.Ed25519,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			return privKey1, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, pubKey1)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Test with same Ed25519 key
	if !key.Equal(privKey1) {
		t.Error("Expected true when comparing with same Ed25519 key")
	}

	// Test with different Ed25519 key
	if key.Equal(privKey2) {
		t.Error("Expected false when comparing with different Ed25519 key")
	}
}

// TestOpaqueEqual_NonSigner tests Equal with non-Signer types
func TestOpaqueEqual_NonSigner(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-nil",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			return privKey, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Test Equal with a non-Signer (forces fallback path at line 175)
	// This tests the edge case where x doesn't implement crypto.Signer
	type nonSigner struct{}
	if key.Equal(nonSigner{}) {
		t.Error("Expected false when comparing with non-Signer")
	}
}

// customPublicKey is a custom public key type for testing
type customPublicKey struct {
	data []byte
}

// customSigner implements crypto.Signer with a custom public key type
type customSigner struct {
	pub crypto.PublicKey
}

func (c *customSigner) Public() crypto.PublicKey {
	return c.pub
}

func (c *customSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return []byte("signature"), nil
}

// TestOpaqueEqual_UnknownKeyType tests Equal with unknown/custom key types
func TestOpaqueEqual_UnknownKeyType(t *testing.T) {
	customPub := &customPublicKey{data: []byte("custom")}
	customPub2 := &customPublicKey{data: []byte("custom2")}

	attrs := &types.KeyAttributes{
		CN:           "test-custom",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	customSig1 := &customSigner{pub: customPub}
	customSig2 := &customSigner{pub: customPub2}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			return customSig1, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, customPub)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Test with same custom type - should use pointer comparison at line 172
	if !key.Equal(customSig1) {
		t.Error("Expected true when comparing with same custom key")
	}

	// Test with different custom key
	// This will fall through to the default case in publicKeysEqual (line 239)
	if key.Equal(customSig2) {
		t.Error("Expected false when comparing different custom keys")
	}
}

// TestOpaqueEqual_RSAKeys tests Equal with RSA key comparisons to ensure publicKeysEqual RSA branch is covered
func TestOpaqueEqual_RSAKeys(t *testing.T) {
	// Generate two different RSA keys
	rsaKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key 1: %v", err)
	}

	rsaKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key 2: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			return rsaKey1, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &rsaKey1.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Test with same RSA key - should use key.Equal
	if !key.Equal(rsaKey1) {
		t.Error("Expected true when comparing with same RSA key")
	}

	// Test with different RSA key - publicKeysEqual should be called
	if key.Equal(rsaKey2) {
		t.Error("Expected false when comparing with different RSA key")
	}
}

// TestOpaqueDigest_VerifyMultipleHashAlgorithms tests Digest with all supported algorithms
func TestOpaqueDigest_VerifyMultipleHashAlgorithms(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	testData := []byte("test data for hashing")

	tests := []struct {
		name         string
		hash         crypto.Hash
		expectedSize int
	}{
		{"SHA256", crypto.SHA256, 32},
		{"SHA384", crypto.SHA384, 48},
		{"SHA512", crypto.SHA512, 64},
		{"SHA3_256", crypto.SHA3_256, 32},
		{"SHA3_384", crypto.SHA3_384, 48},
		{"SHA3_512", crypto.SHA3_512, 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.RSA,
				Hash:         tt.hash,
			}

			key, err := NewOpaqueKey(&mockKeyStore{}, attrs, &privKey.PublicKey)
			if err != nil {
				t.Fatalf("failed to create opaque key: %v", err)
			}

			digest, err := key.Digest(testData)
			if err != nil {
				t.Fatalf("Digest() failed: %v", err)
			}

			if len(digest) != tt.expectedSize {
				t.Errorf("expected digest size %d, got %d", tt.expectedSize, len(digest))
			}

			// Verify against expected digest
			hasher := tt.hash.New()
			hasher.Write(testData)
			expected := hasher.Sum(nil)

			if string(digest) != string(expected) {
				t.Error("digest mismatch")
			}
		})
	}
}

// keyWithControlledEqual is a test helper that implements Equal with controllable behavior
type keyWithControlledEqual struct {
	wrapped *rsa.PrivateKey
	eqValue bool // Control what Equal returns
}

func (c *keyWithControlledEqual) Public() crypto.PublicKey {
	return c.wrapped.Public()
}

func (c *keyWithControlledEqual) Equal(x crypto.PrivateKey) bool {
	return c.eqValue
}

func (c *keyWithControlledEqual) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return c.wrapped.Sign(rand, digest, opts)
}

// signerWithoutEqual is a Signer that does NOT implement Equal, to force publicKeysEqual to be called
type signerWithoutEqual struct {
	privKey *rsa.PrivateKey
	pubKey  crypto.PublicKey
}

func (s *signerWithoutEqual) Public() crypto.PublicKey {
	return s.pubKey
}

func (s *signerWithoutEqual) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.privKey.Sign(rand, digest, opts)
}

// TestOpaqueEqual_WithEqualMethodImplementation tests the Equal method path at line 165-166
func TestOpaqueEqual_WithEqualMethodImplementation(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	customKey := &keyWithControlledEqual{wrapped: rsaKey, eqValue: true}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			// Return the custom key which implements Equal
			return customKey, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Test that Equal delegates to the key's Equal method
	// Since customKey.Equal is set to return true, result should be true
	if !key.Equal(rsaKey) {
		t.Error("Expected true - Equal should delegate to key's Equal method")
	}

	// Test with eqValue=false
	customKey.eqValue = false
	if key.Equal(rsaKey) {
		t.Error("Expected false - Equal should delegate to key's Equal method")
	}
}

// TestPublicKeysEqual_RSATypeMismatch tests publicKeysEqual with RSA vs non-RSA comparison
func TestPublicKeysEqual_RSATypeMismatch(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-rsa",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			return rsaKey, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Comparing RSA key (stored) with ECDSA key (passed) should return false
	// This exercises the type mismatch in the RSA case of publicKeysEqual
	if key.Equal(ecdsaKey) {
		t.Error("Expected false when comparing RSA with ECDSA key")
	}
}

// TestPublicKeysEqual_ECDSATypeMismatch tests publicKeysEqual with ECDSA vs non-ECDSA
func TestPublicKeysEqual_ECDSATypeMismatch(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-ecdsa",
		KeyAlgorithm: x509.ECDSA,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			return ecdsaKey, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &ecdsaKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Comparing ECDSA key (stored) with RSA key (passed) should return false
	// This exercises the type mismatch in the ECDSA case of publicKeysEqual
	if key.Equal(rsaKey) {
		t.Error("Expected false when comparing ECDSA with RSA key")
	}
}

// TestPublicKeysEqual_Ed25519TypeMismatch tests publicKeysEqual with Ed25519 vs non-Ed25519
func TestPublicKeysEqual_Ed25519TypeMismatch(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-ed25519",
		KeyAlgorithm: x509.Ed25519,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			return privKey, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, pubKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Comparing Ed25519 key (stored) with RSA key (passed) should return false
	// This exercises the type mismatch in the Ed25519 case of publicKeysEqual
	if key.Equal(rsaKey) {
		t.Error("Expected false when comparing Ed25519 with RSA key")
	}
}

// TestOpaqueEqual_NilXPublicKey tests Equal when x doesn't implement Signer and Equal path returns false
func TestOpaqueEqual_NilXPublicKey(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			return privKey, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Test Equal with a type that is not a Signer (forces line 175 to execute)
	type notASigner struct{}
	if key.Equal(notASigner{}) {
		t.Error("Expected false when comparing with non-Signer type")
	}
}

// TestPublicKeysEqual_Ed25519MismatchInTypeAssertion tests publicKeysEqual when Ed25519 assertion fails
func TestPublicKeysEqual_Ed25519MismatchInTypeAssertion(t *testing.T) {
	// Generate an Ed25519 key but wrap the public key
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	// Generate an ECDSA key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-ed25519",
		KeyAlgorithm: x509.Ed25519,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			return privKey, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, pubKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Compare Ed25519 with ECDSA - this will call publicKeysEqual with Ed25519 public key
	// and ECDSA public key, causing the type assertion on line 231 to fail
	if key.Equal(ecdsaKey) {
		t.Error("Expected false when comparing Ed25519 with ECDSA")
	}
}

// TestPublicKeysEqual_RSAMismatchInTypeAssertion tests publicKeysEqual when RSA type assertion fails
// By using signerWithoutEqual that returns ECDSA public key, we force the RSA type assertion to fail
func TestPublicKeysEqual_RSAMismatchInTypeAssertion(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-rsa",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			// Return a signer without Equal that returns RSA public key
			signer := &signerWithoutEqual{privKey: rsaKey, pubKey: &rsaKey.PublicKey}
			return signer, nil
		},
	}

	// Create opaque key with RSA's public key
	key, err := NewOpaqueKey(keyStore, attrs, &rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Create a signer that returns ECDSA public key
	// This will cause publicKeysEqual to be called with RSA pub and ECDSA pub
	// The RSA type assertion will fail, hitting line 216-218
	ecdsaSigner := &signerWithoutEqual{privKey: rsaKey, pubKey: &ecdsaKey.PublicKey}

	if key.Equal(ecdsaSigner) {
		t.Error("Expected false when comparing RSA with ECDSA public keys")
	}
}

// TestPublicKeysEqual_ECDSAMismatchInTypeAssertion tests publicKeysEqual when ECDSA assertion fails
func TestPublicKeysEqual_ECDSAMismatchInTypeAssertion(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-ecdsa",
		KeyAlgorithm: x509.ECDSA,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			// Return a signer without Equal that returns ECDSA public key
			signer := &signerWithoutEqual{privKey: rsaKey, pubKey: &ecdsaKey.PublicKey}
			return signer, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &ecdsaKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Create a signer that returns RSA public key
	// This will cause publicKeysEqual to be called with ECDSA pub and RSA pub
	// The ECDSA type assertion will fail, hitting line 223-225
	rsaSigner := &signerWithoutEqual{privKey: rsaKey, pubKey: &rsaKey.PublicKey}

	if key.Equal(rsaSigner) {
		t.Error("Expected false when comparing ECDSA with RSA public keys")
	}
}

// nilPublicKeySigner is a test helper that returns nil for Public()
type nilPublicKeySigner struct{}

func (n *nilPublicKeySigner) Public() crypto.PublicKey {
	return nil
}

func (n *nilPublicKeySigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

// TestPublicKeysEqual_WithNilPublicKey tests publicKeysEqual with nil public key
func TestPublicKeysEqual_WithNilPublicKey(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	// Create a signer that returns nil for Public()
	nilSigner := &nilPublicKeySigner{}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			// Return a signer without Equal to force publicKeysEqual to be called
			signer := &signerWithoutEqual{privKey: privKey, pubKey: &privKey.PublicKey}
			return signer, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Since nilSigner.Public() returns nil, publicKeysEqual will be called with
	// (&privKey.PublicKey, nil) which hits line 209-211
	result := key.Equal(nilSigner)
	if result {
		t.Error("Expected false when comparing RSA with nil public key")
	}
}

// TestPublicKeysEqual_NilKeys tests publicKeysEqual with nil keys
func TestPublicKeysEqual_NilKeys(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			return privKey, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Compare with nil should return false
	if key.Equal(nil) {
		t.Error("Expected false when comparing with nil")
	}
}

// TestOpaqueEqual_MixedECDSACurves tests ECDSA publicKeysEqual with different curves
func TestOpaqueEqual_MixedECDSACurves(t *testing.T) {
	// Generate ECDSA keys on different curves
	ecdsaP256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate P256 key: %v", err)
	}

	ecdsaP384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate P384 key: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "test-ecdsa",
		KeyAlgorithm: x509.ECDSA,
		Hash:         crypto.SHA256,
	}

	keyStore := &mockKeyStore{
		getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			return ecdsaP256, nil
		},
	}

	key, err := NewOpaqueKey(keyStore, attrs, &ecdsaP256.PublicKey)
	if err != nil {
		t.Fatalf("failed to create opaque key: %v", err)
	}

	// Comparing P256 with P384 should return false
	if key.Equal(ecdsaP384) {
		t.Error("Expected false when comparing ECDSA keys with different curves")
	}
}

// mockHasherError creates a mock hasher that fails on Write
type mockHasherError struct {
	writeError bool
	shortWrite bool
	written    int
}

func (m *mockHasherError) Write(p []byte) (n int, err error) {
	if m.writeError {
		return 0, errors.New("mock write error")
	}
	if m.shortWrite {
		return len(p) - 1, nil // Incomplete write
	}
	return len(p), nil
}

func (m *mockHasherError) Sum(b []byte) []byte {
	return []byte("mock sum")
}

func (m *mockHasherError) Reset() {}

func (m *mockHasherError) Size() int {
	return 32
}

func (m *mockHasherError) BlockSize() int {
	return 64
}

// TestPublicKeysEqual_DirectCall tests publicKeysEqual directly by calling it through Equal()
// This test targets the uncovered ECDSA and Ed25519 branches
func TestPublicKeysEqual_DirectCall(t *testing.T) {
	// Test ECDSA vs RSA mismatch to trigger publicKeysEqual ECDSA branch
	t.Run("ECDSA_vs_RSA_mismatch", func(t *testing.T) {
		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}

		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}

		attrs := &types.KeyAttributes{
			CN:           "test-mixed",
			KeyAlgorithm: x509.ECDSA,
			Hash:         crypto.SHA256,
		}

		keyStore := &mockKeyStore{
			getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
				return ecdsaKey, nil
			},
		}

		key, err := NewOpaqueKey(keyStore, attrs, &ecdsaKey.PublicKey)
		if err != nil {
			t.Fatalf("failed to create opaque key: %v", err)
		}

		// Comparing ECDSA key with RSA key should return false
		// This will trigger the publicKeysEqual ECDSA branch
		// rsaKey implements crypto.Signer, so Equal() will call publicKeysEqual
		if key.Equal(rsaKey) {
			t.Error("Expected false when comparing ECDSA with RSA key")
		}
	})

	// Test Ed25519 vs RSA mismatch to trigger publicKeysEqual Ed25519 branch
	t.Run("Ed25519_vs_RSA_mismatch", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate Ed25519 key: %v", err)
		}

		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}

		attrs := &types.KeyAttributes{
			CN:           "test-mixed",
			KeyAlgorithm: x509.Ed25519,
			Hash:         crypto.SHA256,
		}

		keyStore := &mockKeyStore{
			getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
				return privKey, nil
			},
		}

		key, err := NewOpaqueKey(keyStore, attrs, pubKey)
		if err != nil {
			t.Fatalf("failed to create opaque key: %v", err)
		}

		// Comparing Ed25519 key with RSA key should return false
		// This will trigger the publicKeysEqual Ed25519 branch
		if key.Equal(rsaKey) {
			t.Error("Expected false when comparing Ed25519 with RSA key")
		}
	})

	// Test Ed25519 vs ECDSA mismatch to trigger publicKeysEqual Ed25519 branch
	t.Run("Ed25519_vs_ECDSA_mismatch", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate Ed25519 key: %v", err)
		}

		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}

		attrs := &types.KeyAttributes{
			CN:           "test-mixed-ecdsa",
			KeyAlgorithm: x509.Ed25519,
			Hash:         crypto.SHA256,
		}

		keyStore := &mockKeyStore{
			getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
				return privKey, nil
			},
		}

		key, err := NewOpaqueKey(keyStore, attrs, pubKey)
		if err != nil {
			t.Fatalf("failed to create opaque key: %v", err)
		}

		// Comparing Ed25519 key with ECDSA key should return false
		// This will trigger the publicKeysEqual Ed25519 branch with type mismatch
		if key.Equal(ecdsaKey) {
			t.Error("Expected false when comparing Ed25519 with ECDSA key")
		}
	})

	// Test ECDSA with same curve but different keys - triggers ECDSA branch
	t.Run("ECDSA_different_same_curve", func(t *testing.T) {
		privKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate first ECDSA key: %v", err)
		}

		privKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate second ECDSA key: %v", err)
		}

		attrs := &types.KeyAttributes{
			CN:           "test-ecdsa",
			KeyAlgorithm: x509.ECDSA,
			Hash:         crypto.SHA256,
		}

		keyStore := &mockKeyStore{
			getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
				return privKey1, nil
			},
		}

		key, err := NewOpaqueKey(keyStore, attrs, &privKey1.PublicKey)
		if err != nil {
			t.Fatalf("failed to create opaque key: %v", err)
		}

		// Comparing with a different ECDSA key should trigger publicKeysEqual
		// This will execute the ECDSA branch in publicKeysEqual and return false
		if key.Equal(privKey2) {
			t.Error("Expected false when comparing different ECDSA keys")
		}
	})

	// Test Ed25519 with different keys - triggers Ed25519 branch
	t.Run("Ed25519_different_keys", func(t *testing.T) {
		pubKey1, privKey1, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate first Ed25519 key: %v", err)
		}

		_, privKey2, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate second Ed25519 key: %v", err)
		}

		attrs := &types.KeyAttributes{
			CN:           "test-ed25519",
			KeyAlgorithm: x509.Ed25519,
			Hash:         crypto.SHA256,
		}

		keyStore := &mockKeyStore{
			getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
				return privKey1, nil
			},
		}

		key, err := NewOpaqueKey(keyStore, attrs, pubKey1)
		if err != nil {
			t.Fatalf("failed to create opaque key: %v", err)
		}

		// Comparing with a different Ed25519 key should trigger publicKeysEqual
		// This will execute the Ed25519 branch in publicKeysEqual and return false
		if key.Equal(privKey2) {
			t.Error("Expected false when comparing different Ed25519 keys")
		}

		// Test with same key - should return true
		if !key.Equal(privKey1) {
			t.Error("Expected true when comparing with same Ed25519 key")
		}
	})

	// Test Ed25519 with same key - triggers Ed25519 branch with bytes.Equal returning true
	t.Run("Ed25519_same_key", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate Ed25519 key: %v", err)
		}

		attrs := &types.KeyAttributes{
			CN:           "test-ed25519-same",
			KeyAlgorithm: x509.Ed25519,
			Hash:         crypto.SHA256,
		}

		keyStore := &mockKeyStore{
			getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
				return privKey, nil
			},
		}

		key, err := NewOpaqueKey(keyStore, attrs, pubKey)
		if err != nil {
			t.Fatalf("failed to create opaque key: %v", err)
		}

		// Test with the same Ed25519 key - publicKeysEqual will be called
		// with ed25519.PublicKey instances and bytes.Equal should return true
		if !key.Equal(privKey) {
			t.Error("Expected true when comparing with same Ed25519 key")
		}
	})

	// Test nil public key handling
	t.Run("nil_public_keys", func(t *testing.T) {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}

		attrs := &types.KeyAttributes{
			CN:           "test-nil",
			KeyAlgorithm: x509.ECDSA,
			Hash:         crypto.SHA256,
		}

		keyStore := &mockKeyStore{
			getKeyFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
				return privKey, nil
			},
		}

		key, err := NewOpaqueKey(keyStore, attrs, &privKey.PublicKey)
		if err != nil {
			t.Fatalf("failed to create opaque key: %v", err)
		}

		// Test with nil comparison key
		if key.Equal(nil) {
			t.Error("Expected false when comparing with nil")
		}
	})

}
